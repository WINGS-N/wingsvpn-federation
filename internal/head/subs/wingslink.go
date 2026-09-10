package subs

import (
	"bytes"
	"compress/zlib"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"

	"github.com/andybalholm/brotli"
	"google.golang.org/protobuf/proto"

	wingsvpb "wingsnet.org/federation/gen/wingsvpb"
)

// Форматы ссылки приложения: за префиксом идёт base64url от байта формата и
// сжатого Config. Основной - brotli, старый zlib читается для совместимости
const (
	scheme                = "wingsv://"
	formatProtobufDeflate = 0x12
	formatProtobufBrotli  = 0x13
	// brotliQuality - пятый уровень. Одиннадцатый на этих данных даёт те же
	// байты за время в полсотни раз большее
	brotliQuality = 5
)

// EncodeConfig собирает ссылку приложения из конфига
func EncodeConfig(cfg *wingsvpb.Config) (string, error) {
	raw, err := proto.Marshal(cfg)
	if err != nil {
		return "", err
	}
	packed, err := packConfig(raw)
	if err != nil {
		return "", err
	}
	return scheme + base64.RawURLEncoding.EncodeToString(packed), nil
}

// Turn - профиль VK TURN, каким его видит приложение
type Turn struct {
	ID       string
	Name     string
	Endpoint string
	ClientID string
	Token    string
	// Settings - чем прикидываться и как обфусцировать. Едут с сервера, потому
	// что инфраструктура звонков меняется, а ждать, пока все обновят приложение,
	// значит оставить людей без связи на неделю
	Settings TurnSettings
}

// TurnSettings - то, что оператор задаёт всем выданным профилям разом
type TurnSettings struct {
	BrowserFingerprint string
	WrapMode           string
	WrapCipher         string
	DNSMode            string
	VKAuthMode         string
	// VKLinks - пул ссылок на звонки, общий для всего флота. Одна ссылка это
	// один сдохший звонок до полной потери связи, а набирать их руками человек
	// не должен
	VKLinks []string
}

// Bundle собирает конфиг из обоих протоколов: Xray-профили и VK TURN рядом,
// одним списком серверов
func Bundle(links []string, turns []Turn, label string) *wingsvpb.Config {
	cfg := XrayBundle(links, label)
	if len(turns) == 0 {
		return cfg
	}
	// Тип остаётся XRAY: CONFIG_TYPE_ALL приложение читает как полный бэкап
	// настроек и применяет его целиком, а подписка - это только профили
	for _, t := range turns {
		cfg.Turn = ensureTurn(cfg.Turn)
		cfg.Turn.Profiles = append(cfg.Turn.Profiles, &wingsvpb.TurnProfile{
			Id:                t.ID,
			Title:             t.Name,
			VkTurnEndpoint:    t.Endpoint,
			SubscriptionTitle: label,
			// Транспорт приложение получает у самой ноды: ключи wg рождаются
			// на ней, а башка их не держит и держать не должна
			WgProvisioned:     true,
			ProvisionClientId: t.ClientID,
			ProvisionToken:    []byte(t.Token),
			TransportKind:     "wg",
			// Профиль выдан, а не настроен человеком: править его поля значит
			// сломать себе связь и пойти писать, что у нас не работает
			ManagedSettings: true,
			VkAuthMode:      orDefault(t.Settings.VKAuthMode, "anonymous"),
			DnsMode:         orDefault(t.Settings.DNSMode, "auto"),
			Config: &wingsvpb.Turn{
				Links:              t.Settings.VKLinks,
				BrowserFingerprint: t.Settings.BrowserFingerprint,
				// Обфускация обязательна: голый поток по нынешним временам это
				// подарок цензору, а выданному профилю выбирать тут нечего
				WrapMode:    wrapModeOf(t.Settings.WrapMode),
				WrapCiphers: wrapCiphersOf(t.Settings.WrapCipher),
			},
		})
	}
	return cfg
}

func ensureTurn(turn *wingsvpb.Turn) *wingsvpb.Turn {
	if turn == nil {
		return &wingsvpb.Turn{}
	}
	return turn
}

// XrayBundle собирает один Config со всеми выданными профилями. Ссылки внутри
// остаются в своём виде: приложение хранит raw_link и отдаёт его ядру как есть
func XrayBundle(links []string, label string) *wingsvpb.Config {
	cfg := &wingsvpb.Config{
		Ver:     1,
		Type:    wingsvpb.ConfigType_CONFIG_TYPE_XRAY,
		Backend: wingsvpb.BackendType_BACKEND_TYPE_XRAY,
		Xray:    &wingsvpb.Xray{},
	}
	for i, link := range links {
		profile := &wingsvpb.VlessProfile{
			Id:                profileID(link),
			Title:             linkName(link, fmt.Sprintf("%s %d", label, i+1)),
			RawLink:           link,
			SubscriptionTitle: label,
		}
		// Адрес ноды отдельным полем: по нему клиент подписывает расписку, а
		// вытаскивать его из ссылки на устройстве значит держать второй разбор
		// vless там, где он нахуй не нужен
		if host, port := endpointOf(link); host != "" {
			profile.Address = host
			if port > 0 {
				profile.Port = proto.Uint32(port)
			}
		}
		cfg.Xray.Profiles = append(cfg.Xray.Profiles, profile)
	}
	if len(cfg.Xray.Profiles) > 0 {
		cfg.Xray.ActiveProfileId = cfg.Xray.Profiles[0].GetId()
	}
	return cfg
}

// profileID считает идентификатор от самой ссылки, а НЕ от места в списке.
//
// Порядок в выдаче гуляет как хочет: купленный сервер встаёт перед своими,
// нода уходит в парк, и номер по позиции переезжает на другой сервер нахуй.
// Приложение держит профили по id, поэтому два разных сервера с одним id
// склеиваются в один, и человек тычет в строку, которая уже ничья.
//
// Имя в счёт не идёт: продавец переименовал сервер - это тот же сервер
func profileID(link string) string {
	base := link
	if idx := strings.LastIndex(base, "#"); idx >= 0 {
		base = base[:idx]
	}
	sum := sha512.Sum512_256([]byte(base))
	return "fed-" + hex.EncodeToString(sum[:6])
}

// linkName достаёт имя сервера из хвоста ссылки: там оно уже собрано со
// страной и транспортом, и человек ждёт в приложении ровно его
// endpointOf достаёт хост и порт из vless-ссылки
func endpointOf(link string) (string, uint32) {
	parsed, err := url.Parse(link)
	if err != nil || parsed.Host == "" {
		return "", 0
	}
	host := parsed.Hostname()
	port64, err := strconv.ParseUint(parsed.Port(), 10, 32)
	if err != nil {
		return host, 0
	}
	return host, uint32(port64)
}

func linkName(link, fallback string) string {
	idx := strings.LastIndex(link, "#")
	if idx < 0 || idx+1 >= len(link) {
		return fallback
	}
	name := link[idx+1:]
	if decoded, err := url.QueryUnescape(name); err == nil {
		name = decoded
	}
	if strings.TrimSpace(name) == "" {
		return fallback
	}
	return name
}

// packConfig сжимает и подписывает байтом формата
func packConfig(raw []byte) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte(formatProtobufBrotli)
	writer := brotli.NewWriterLevel(&buf, brotliQuality)
	if _, err := writer.Write(raw); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// EncodeConfigBytes отдаёт тот же кадр без base64. Подписка забирается
// приложением напрямую, и кодировать её в текст значит добавить треть длины
// на ровном месте
func EncodeConfigBytes(cfg *wingsvpb.Config) ([]byte, error) {
	raw, err := proto.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	return packConfig(raw)
}

// DecodeConfig разбирает ссылку обратно
func DecodeConfig(link string) (*wingsvpb.Config, error) {
	payload := strings.TrimPrefix(strings.TrimSpace(link), scheme)
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(payload, "="))
	if err != nil {
		return nil, err
	}
	return DecodeFrame(raw)
}

// DecodeFrame разбирает кадр: байт формата и сжатый Config
func DecodeFrame(raw []byte) (*wingsvpb.Config, error) {
	if len(raw) < 2 {
		return nil, fmt.Errorf("subs: payload too short")
	}
	var (
		body []byte
		err  error
	)
	switch raw[0] {
	case formatProtobufBrotli:
		body, err = io.ReadAll(brotli.NewReader(bytes.NewReader(raw[1:])))
	case formatProtobufDeflate:
		var reader io.ReadCloser
		if reader, err = zlib.NewReader(bytes.NewReader(raw[1:])); err == nil {
			body, err = io.ReadAll(reader)
			_ = reader.Close()
		}
	default:
		return nil, fmt.Errorf("subs: unsupported link format")
	}
	if err != nil {
		return nil, err
	}
	cfg := &wingsvpb.Config{}
	if err := proto.Unmarshal(body, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// wrapModeOf переводит настройку оператора в то, что понимает приложение.
// По умолчанию требуем обфускацию, а не просто разрешаем
func wrapModeOf(mode string) wingsvpb.WrapMode {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "off":
		return wingsvpb.WrapMode_WRAP_MODE_OFF
	case "preferred", "on":
		return wingsvpb.WrapMode_WRAP_MODE_PREFERRED
	default:
		return wingsvpb.WrapMode_WRAP_MODE_REQUIRED
	}
}

// wrapCiphersOf - чем шифровать. AES-256-GCM первым: он в железе почти везде, а
// ChaCha остаётся для машин без ускорения
func wrapCiphersOf(cipher string) []wingsvpb.WrapCipher {
	switch strings.ToLower(strings.TrimSpace(cipher)) {
	case "srtp-chacha20-poly1305", "chacha":
		return []wingsvpb.WrapCipher{wingsvpb.WrapCipher_WRAP_CIPHER_SRTP_CHACHA20_POLY1305}
	case "srtp-aes-gcm", "aes":
		return []wingsvpb.WrapCipher{wingsvpb.WrapCipher_WRAP_CIPHER_SRTP_AES_256_GCM}
	default:
		return []wingsvpb.WrapCipher{
			wingsvpb.WrapCipher_WRAP_CIPHER_SRTP_AES_256_GCM,
			wingsvpb.WrapCipher_WRAP_CIPHER_SRTP_CHACHA20_POLY1305,
		}
	}
}

// orDefault подставляет значение, когда оператор своё не задал
func orDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
