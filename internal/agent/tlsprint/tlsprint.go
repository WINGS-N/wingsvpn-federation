// Package tlsprint считает отпечаток TLS-клиента и вытаскивает SNI из
// ClientHello.
//
// Копия того, что стоит в нашем форке ядра: у VK TURN сниффера нет вовсе, и
// разбирать хендшейк приходится самим, читая пакеты с wg-интерфейса. Тащить
// ради этого всё ядро зависимостью было бы дороже, чем держать три сотни строк.
//
// Адрес у мобильного меняется законно и в признаки годится хуёво, а набор шифров
// с расширениями прибит к приложению: одна ссылка, с которой лезут пять разных
// TLS-стеков, это какая-то хуйня, а не переезд между сетями
package tlsprint

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

// Print - то, что достали из хендшейка
type Print struct {
	// JA3 - каноническая строка и её MD5. Хэш именно MD5, потому что таким его
	// считает весь мир, и своей солью мы бы просто перестали сходиться с фидами
	JA3     string
	JA3Hash string
	JA4     string
	// ServerName - куда клиент собрался. Для VK TURN это единственный источник
	// доменов: access-лога у релея нет и не будет
	ServerName string
}

// Parse разбирает буфер, начинающийся с TLS-записи. Второе значение false, если
// это не ClientHello или запись пришла обрезанной
func Parse(b []byte) (Print, bool) {
	hello, ok := clientHello(b)
	if !ok {
		return Print{}, false
	}
	h, ok := parseHello(hello)
	if !ok {
		return Print{}, false
	}
	ja3 := buildJA3(h)
	sum := md5.Sum([]byte(ja3))
	return Print{
		JA3: ja3, JA3Hash: hex.EncodeToString(sum[:]),
		JA4: buildJA4(h), ServerName: h.serverName,
	}, true
}

// parseSNI достаёт первое имя из расширения server_name
func parseSNI(body []byte) string {
	// Список имён: два байта общей длины, дальше записи вида тип, длина, имя
	if len(body) < 5 || body[2] != 0x00 {
		return ""
	}
	size := int(binary.BigEndian.Uint16(body[3:5]))
	if size <= 0 || 5+size > len(body) {
		return ""
	}
	name := string(body[5 : 5+size])
	// Имя обязано выглядеть именем: в SNI кладут и всякую дрянь
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '-', r == '_':
		default:
			return ""
		}
	}
	return strings.ToLower(name)
}

// clientHello вынимает тело ClientHello из TLS-записи
func clientHello(b []byte) ([]byte, bool) {
	if len(b) < 9 || b[0] != 0x16 {
		return nil, false
	}
	recordLen := int(binary.BigEndian.Uint16(b[3:5]))
	if recordLen < 4 || 5+recordLen > len(b) {
		return nil, false
	}
	body := b[5 : 5+recordLen]
	if body[0] != 0x01 {
		return nil, false
	}
	helloLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if 4+helloLen > len(body) {
		return nil, false
	}
	return body[4 : 4+helloLen], true
}

// hello - только то, из чего складывается отпечаток
type hello struct {
	version      uint16
	ciphers      []uint16
	extensions   []uint16
	curves       []uint16
	pointFmts    []uint16
	sigAlgs      []uint16
	alpn         string
	hasSNI       bool
	serverName   string
	maxSupported uint16
}

func parseHello(b []byte) (hello, bool) {
	var h hello
	r := reader{b: b}
	h.version = r.u16()
	r.skip(32)
	r.skip(int(r.u8()))
	ciphersLen := int(r.u16())
	if ciphersLen%2 != 0 {
		return h, false
	}
	for i := 0; i < ciphersLen/2; i++ {
		h.ciphers = append(h.ciphers, r.u16())
	}
	r.skip(int(r.u8()))
	if r.bad {
		return h, false
	}
	// Расширений может не быть вовсе, и это законный ClientHello
	if r.left() < 2 {
		return h, true
	}
	extTotal := int(r.u16())
	end := r.i + extTotal
	for r.i < end && !r.bad {
		id := r.u16()
		size := int(r.u16())
		body := r.take(size)
		if r.bad {
			break
		}
		h.extensions = append(h.extensions, id)
		switch id {
		case 0x0000:
			h.hasSNI = true
			h.serverName = parseSNI(body)
		case 0x000a:
			h.curves = parseU16List(body, true)
		case 0x000b:
			for _, v := range body[min(1, len(body)):] {
				h.pointFmts = append(h.pointFmts, uint16(v))
			}
		case 0x000d:
			h.sigAlgs = parseU16List(body, true)
		case 0x0010:
			h.alpn = firstALPN(body)
		case 0x002b:
			for _, v := range parseU16List(body, false) {
				if isGREASE(v) {
					continue
				}
				if v > h.maxSupported {
					h.maxSupported = v
				}
			}
		}
	}
	return h, !r.bad
}

// parseU16List читает список из u16 с двухбайтовой длиной впереди
func parseU16List(b []byte, u16Len bool) []uint16 {
	var skip int
	if u16Len {
		skip = 2
	} else {
		skip = 1
	}
	if len(b) < skip {
		return nil
	}
	body := b[skip:]
	out := make([]uint16, 0, len(body)/2)
	for i := 0; i+1 < len(body); i += 2 {
		out = append(out, binary.BigEndian.Uint16(body[i:i+2]))
	}
	return out
}

// firstALPN отдаёт первый предложенный протокол
func firstALPN(b []byte) string {
	if len(b) < 3 {
		return ""
	}
	size := int(b[2])
	if 3+size > len(b) {
		return ""
	}
	return string(b[3 : 3+size])
}

// isGREASE отсеивает мусорные значения, которыми браузер нарочно засоряет
// списки: они меняются от соединения к соединению, и без фильтра отпечаток
// разъезжается у одного и того же клиента
func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && byte(v>>8) == byte(v)
}

func buildJA3(h hello) string {
	parts := []string{
		strconv.Itoa(int(h.version)),
		joinDash(filterGREASE(h.ciphers)),
		joinDash(filterGREASE(h.extensions)),
		joinDash(filterGREASE(h.curves)),
		joinDash(h.pointFmts),
	}
	return strings.Join(parts, ",")
}

func buildJA4(h hello) string {
	version := "00"
	switch v := h.maxSupported; {
	case v >= 0x0304:
		version = "13"
	case v == 0x0303 || h.version == 0x0303:
		version = "12"
	case v == 0x0302 || h.version == 0x0302:
		version = "11"
	case v == 0x0301 || h.version == 0x0301:
		version = "10"
	}
	sni := "i"
	if h.hasSNI {
		sni = "d"
	}
	ciphers := filterGREASE(h.ciphers)
	exts := filterGREASE(h.extensions)
	alpn := "00"
	if len(h.alpn) > 0 {
		alpn = string(h.alpn[0]) + string(h.alpn[len(h.alpn)-1])
	}
	head := "t" + version + sni + count2(len(ciphers)) + count2(len(exts)) + alpn

	// SNI и ALPN из списка выбрасываются: домен и протокол это про то, куда
	// идут, а отпечаток должен говорить про клиента
	sorted := make([]uint16, 0, len(exts))
	for _, id := range exts {
		if id == 0x0000 || id == 0x0010 {
			continue
		}
		sorted = append(sorted, id)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	sortedCiphers := append([]uint16(nil), ciphers...)
	sort.Slice(sortedCiphers, func(i, j int) bool { return sortedCiphers[i] < sortedCiphers[j] })

	tail := joinHex(sorted)
	if sigs := filterGREASE(h.sigAlgs); len(sigs) > 0 {
		tail += "_" + joinHex(sigs)
	}
	return head + "_" + truncSHA(joinHex(sortedCiphers)) + "_" + truncSHA(tail)
}

// truncSHA - двенадцать знаков хэша, как того требует формат JA4
func truncSHA(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func count2(n int) string {
	if n > 99 {
		n = 99
	}
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

func filterGREASE(in []uint16) []uint16 {
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

func joinDash(in []uint16) string {
	parts := make([]string, 0, len(in))
	for _, v := range in {
		parts = append(parts, strconv.Itoa(int(v)))
	}
	return strings.Join(parts, "-")
}

func joinHex(in []uint16) string {
	parts := make([]string, 0, len(in))
	for _, v := range in {
		parts = append(parts, hex.EncodeToString([]byte{byte(v >> 8), byte(v)}))
	}
	return strings.Join(parts, ",")
}

// reader читает большой порядок байт и запоминает, что вышел за край, чтобы не
// проверять длину на каждом чтении
type reader struct {
	b   []byte
	i   int
	bad bool
}

func (r *reader) u8() uint8 {
	if r.i+1 > len(r.b) {
		r.bad = true
		return 0
	}
	v := r.b[r.i]
	r.i++
	return v
}

func (r *reader) u16() uint16 {
	if r.i+2 > len(r.b) {
		r.bad = true
		return 0
	}
	v := binary.BigEndian.Uint16(r.b[r.i : r.i+2])
	r.i += 2
	return v
}

func (r *reader) take(n int) []byte {
	if n < 0 || r.i+n > len(r.b) {
		r.bad = true
		return nil
	}
	v := r.b[r.i : r.i+n]
	r.i += n
	return v
}

func (r *reader) skip(n int) { r.take(n) }

func (r *reader) left() int { return len(r.b) - r.i }
