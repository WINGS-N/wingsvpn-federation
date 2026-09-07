package chain

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"wingsnet.org/federation/internal/head/payout"
)

// requestTimeout - публичный RPC умеет тупить, но ждать его вечно незачем
const requestTimeout = 20 * time.Second

// Client ходит в RPC цепочки
type Client struct {
	endpoint string
	http     *http.Client
}

func New(endpoint string) *Client {
	return &Client{endpoint: endpoint, http: &http.Client{Timeout: requestTimeout}}
}

type rpcRequest struct {
	Version string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	// Логи симуляции. Без них "Transaction simulation failed" не говорит
	// ничего: программа-то знает, на какой проверке отбилась, а мы нет
	Data struct {
		Logs []string `json:"logs"`
	} `json:"data"`
}

func (c *Client) call(ctx context.Context, method string, params []any, out any) error {
	body, err := json.Marshal(rpcRequest{Version: "2.0", ID: 1, Method: method, Params: params})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *rpcError       `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return err
	}
	if envelope.Error != nil {
		if logs := envelope.Error.Data.Logs; len(logs) > 0 {
			return fmt.Errorf("chain: %s: %s\n%s",
				method, envelope.Error.Message, strings.Join(logs, "\n"))
		}
		return fmt.Errorf("chain: %s: %s", method, envelope.Error.Message)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(envelope.Result, out)
}

// LatestBlockhash - без него транзакцию не собрать: он же и срок её годности
func (c *Client) LatestBlockhash(ctx context.Context) ([32]byte, error) {
	var out struct {
		Value struct {
			Blockhash string `json:"blockhash"`
		} `json:"value"`
	}
	if err := c.call(ctx, "getLatestBlockhash", []any{map[string]any{"commitment": "finalized"}}, &out); err != nil {
		return [32]byte{}, err
	}
	raw, err := payout.DecodeBase58(out.Value.Blockhash)
	if err != nil {
		return [32]byte{}, err
	}
	if len(raw) != 32 {
		return [32]byte{}, errors.New("chain: blockhash is not 32 bytes")
	}
	var hash [32]byte
	copy(hash[:], raw)
	return hash, nil
}

// MinimumBalance - сколько лампортов нужно аккаунту, чтобы не платить ренту
func (c *Client) MinimumBalance(ctx context.Context, size int) (uint64, error) {
	var lamports uint64
	if err := c.call(ctx, "getMinimumBalanceForRentExemption", []any{size}, &lamports); err != nil {
		return 0, err
	}
	return lamports, nil
}

// Send отправляет подписанную транзакцию и отдаёт её подпись
func (c *Client) Send(ctx context.Context, transaction []byte) (string, error) {
	var signature string
	params := []any{
		base64.StdEncoding.EncodeToString(transaction),
		map[string]any{"encoding": "base64", "preflightCommitment": "finalized"},
	}
	if err := c.call(ctx, "sendTransaction", params, &signature); err != nil {
		return "", err
	}
	return signature, nil
}

// Confirmed - доехала ли транзакция. Публикация эпохи не считается сделанной,
// пока цепочка её не финализировала: иначе башка отметит выплату, которой нет
func (c *Client) Confirmed(ctx context.Context, signature string) (bool, error) {
	var out struct {
		Value []*struct {
			ConfirmationStatus string      `json:"confirmationStatus"`
			Err                any         `json:"err"`
			Slot               json.Number `json:"slot"`
		} `json:"value"`
	}
	params := []any{[]string{signature}, map[string]any{"searchTransactionHistory": true}}
	if err := c.call(ctx, "getSignatureStatuses", params, &out); err != nil {
		return false, err
	}
	if len(out.Value) == 0 || out.Value[0] == nil {
		return false, nil
	}
	if out.Value[0].Err != nil {
		return false, fmt.Errorf("chain: transaction %s failed on chain", signature)
	}
	return out.Value[0].ConfirmationStatus == "finalized", nil
}

// Signer - ключ башки, которым подписываются публикации
type Signer struct {
	Public Pubkey
	secret ed25519.PrivateKey
}

// NewSigner берёт ключ в том же виде, в каком его хранит solana-keygen: 64
// байта, где первые 32 это seed
func NewSigner(raw []byte) (*Signer, error) {
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("chain: the key is %d bytes, want %d", len(raw), ed25519.PrivateKeySize)
	}
	secret := ed25519.PrivateKey(raw)
	var public Pubkey
	copy(public[:], secret.Public().(ed25519.PublicKey))
	return &Signer{Public: public, secret: secret}, nil
}

// Sign собирает транзакцию из одной инструкции и подписывает её
func (s *Signer) Sign(blockhash [32]byte, instruction Instruction) ([]byte, error) {
	return s.SignMany(blockhash, []Instruction{instruction}, nil)
}

// SignMany подписывает несколько инструкций разом.
//
// Заведение нового аккаунта требует его собственной подписи, поэтому чужие ключи
// передаются отдельно: без них цепочка отобьёт создание
func (s *Signer) SignMany(
	blockhash [32]byte,
	instructions []Instruction,
	extra map[Pubkey]ed25519.PrivateKey,
) ([]byte, error) {
	message, signers, err := BuildMessage(s.Public, blockhash, instructions)
	if err != nil {
		return nil, err
	}
	keys := map[Pubkey]ed25519.PrivateKey{s.Public: s.secret}
	for key, secret := range extra {
		keys[key] = secret
	}
	return SignTransaction(message, signers, keys)
}

// Secret отдаёт ключ для тех случаев, когда подписантов несколько
func (s *Signer) Secret() ed25519.PrivateKey { return s.secret }

// AccountData отдаёт сырые данные аккаунта
// ErrNoAccount - в цепочке пусто. Отдельной ошибкой, потому что "аккаунта ещё
// нет" это законный ответ для того, кто его как раз собрался заводить
var ErrNoAccount = errors.New("chain: no such account on chain")

func (c *Client) AccountData(ctx context.Context, key Pubkey) ([]byte, error) {
	var out struct {
		Value *struct {
			Data []string `json:"data"`
		} `json:"value"`
	}
	params := []any{Base58(key), map[string]any{"encoding": "base64"}}
	if err := c.call(ctx, "getAccountInfo", params, &out); err != nil {
		return nil, err
	}
	if out.Value == nil || len(out.Value.Data) == 0 {
		return nil, ErrNoAccount
	}
	return base64.StdEncoding.DecodeString(out.Value.Data[0])
}
