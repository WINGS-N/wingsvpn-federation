package profiles

import "testing"

// Имя сервера читается человеком, а не машиной: флаг, страна, номер, транспорт
func TestDisplayName(t *testing.T) {
	cases := []struct {
		country   string
		index     int
		transport string
		want      string
	}{
		{"RU", 1, "tcp", "\U0001F1F7\U0001F1FA Russia #1 / TCP"},
		{"RU", 2, "xhttp", "\U0001F1F7\U0001F1FA Russia #2 / XHTTP"},
		{"DE", 1, "vktp", "\U0001F1E9\U0001F1EA\U0001F3F3 Germany #1 / VKTP"},
		{"", 3, "tcp", "Node #3 / TCP"},
		{"ZZ", 1, "tcp", "\U0001F1FF\U0001F1FF ZZ #1 / TCP"},
	}
	for _, c := range cases {
		if got := DisplayName(c.country, c.index, c.transport); got != c.want {
			t.Errorf("DisplayName(%q,%d,%q) = %q, want %q", c.country, c.index, c.transport, got, c.want)
		}
	}
}

// Транспорт дописывается к готовому имени, а не подменяет его
func TestLinkTitle(t *testing.T) {
	if got := linkTitle("\U0001F1F7\U0001F1FA Russia #1", "xhttp"); got != "\U0001F1F7\U0001F1FA Russia #1 / XHTTP" {
		t.Errorf("linkTitle = %q", got)
	}
	if got := linkTitle("", "tcp"); got != "TCP" {
		t.Errorf("пустое имя = %q", got)
	}
}
