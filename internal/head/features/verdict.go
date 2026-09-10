package features

import (
	fedpb "wingsnet.org/federation/gen/fedpb"
)

// Finding - обвинение, выведенное из формы поведения
type Finding struct {
	Kind fedpb.AbuseKind
	// Count - величина, а не число срабатываний. Башка насыщает её сама
	Count uint32
	// Why - человеческое объяснение, чтобы в панели было видно за что
	Why string
}

// Пороги подобраны так, чтобы обычный телефон не задел ни одного: у живого
// человека десятки доменов за час, жирные ответы и хоть одно долгое соединение.
// Промахнёшься тут - и выебешь невиновного, а он за это платит доступом
const (
	// scanDomainsPerHour - столько разных имён за час человек не открывает
	scanDomainsPerHour = 120
	// tinyExchange - средний обмен, ниже которого это перебор, а не просмотр
	tinyExchange = 900
	// uploadHeavy - перекос в отдачу, за которым начинается раздача
	uploadHeavy = 0.75
	// randomHeavy - доля сгенерированных имён
	randomHeavy = 0.25
	// randomOwnersMin - и хозяев у таких имён должно быть несколько. Один
	// сервис с шардами это ютуб или инстаграм, а не перебор доменов
	randomOwnersMin = 3
	// randomOwnersSeen - сколько владельцев вообще надо увидеть, чтобы доля
	// что-то значила. На двенадцати три странных имени дают ровно порог, и
	// человек уезжает в карантин за десять минут листания ленты
	randomOwnersSeen = 20
	// bareHeavy - доля соединений на голый адрес
	bareHeavy = 0.6
	// portScanPorts - столько разных портов трогает только сканер
	portScanPorts = 25
	// submissionSpread - столько разных почтовых серверов у человека не бывает.
	// Свой ящик это один сервер, рабочий второй, всё остальное это рассылка
	submissionSpread = 8
	// minRequests - меньше этого числа обращений судить не о чем
	minRequests = 60
	// printSpread - столько разных TLS-стеков за окно с одного устройства не
	// вылезет. Через туннель прёт весь телефон, приложений там дохуя, но почти
	// все ходят системным стеком, а свой держат единицы: браузер, пара
	// мессенджеров, что-то на Go. Порог с запасом, потому что проёб тут стоит
	// человеку доступа
	printSpread = 10
	// printFlat - доля самого частого стека, ниже которой картина ровная. У
	// одного устройства системный стек забирает почти всё, у нескольких людей
	// доли размазываются
	printFlat = 0.4
	// FreshDomainDays - моложе скольких дней домен считается свежим. Месяц:
	// фишинговая лавка столько и живёт, а нормальный бизнес заводит домен
	// задолго до того, как к нему пойдут люди
	FreshDomainDays = 30
	// freshDomainHeavy - доля свежих имён среди тех, чей возраст известен. У
	// человека свежак попадается штучно: зашёл на новый сервис и ушёл. Когда
	// ими забита половина похода - это уже не совпадение
	freshDomainHeavy = 0.5
	// freshDomainMin - и штук должно быть несколько. Один свежий домен есть у
	// кого угодно, обвинять за него значит выебать невиновного
	freshDomainMin = 5
)

// Judge выводит обвинения из вектора.
//
// Ни одного домена и ни одного списка, всё по форме. Поднять свой домен - дело
// пяти минут, а вот перестать выглядеть как перебор, продолжая перебирать, хер
// получится
func Judge(v Vector) []Finding {
	if v.Requests < minRequests {
		return nil
	}
	var out []Finding

	// Ебанина из имён, крошечный обмен и ни одного долгого соединения - это
	// чекер или сканер, а не человек за браузером
	if v.DomainsPerHour >= scanDomainsPerHour && v.BytesPerRequest <= tinyExchange && v.LongLivedShare == 0 {
		out = append(out, Finding{
			Kind:  fedpb.AbuseKind_ABUSE_KIND_PORT_SCAN,
			Count: uint32(v.DomainsPerHour),
			Why:   "много имён подряд, ответы крошечные, ни одного долгого соединения",
		})
	}

	// Порт между почтовыми серверами. Клиентские программы туда не лезут, а
	// операторы его режут, так что это почти наверняка спам
	if v.RelayPortHits > 0 {
		out = append(out, Finding{
			Kind:  fedpb.AbuseKind_ABUSE_KIND_MAIL_PORT,
			Count: uint32(v.RelayPortHits),
			Why:   "исходящие соединения на порт между почтовыми серверами",
		})
	}

	// Отправка почты из программы - обычное дело и сама по себе никого не
	// обвиняет, иначе выебем каждого, кто настроил ящик на телефоне. Рассылкой
	// её делает россыпь чужих релеев: свой ящик живёт на одном, ну на двух
	if v.SubmissionTargets >= submissionSpread {
		out = append(out, Finding{
			Kind:  fedpb.AbuseKind_ABUSE_KIND_MAIL_PORT,
			Count: v.SubmissionTargets,
			Why:   "почта уходит через десятки разных серверов",
		})
	}

	// Разные TLS-стеки в товарном количестве, да ещё и ровными долями: одна
	// ссылка на несколько устройств выглядит именно так
	if v.DistinctPrints >= printSpread && v.TopPrintShare > 0 && v.TopPrintShare < printFlat {
		out = append(out, Finding{
			Kind:  fedpb.AbuseKind_ABUSE_KIND_CLIENT_SPREAD,
			Count: uint32(v.DistinctPrints),
			Why:   "наружу лезут разные TLS-стеки ровными долями, как с нескольких устройств",
		})
	}

	if v.PeerPortHits > 0 {
		out = append(out, Finding{
			Kind:  fedpb.AbuseKind_ABUSE_KIND_TORRENT,
			Count: uint32(v.PeerPortHits),
			Why:   "обмен по портам bittorrent",
		})
	}

	// Раздача перекошена вверх. Мелочь по объёму отсекаем, иначе сюда влетит
	// любой, кто отправил фотку и закрыл приложение
	if v.UpRatio >= uploadHeavy && v.BytesPerRequest > tinyExchange {
		out = append(out, Finding{
			Kind:  fedpb.AbuseKind_ABUSE_KIND_UPLOAD_HEAVY,
			Count: uint32(v.UpRatio * 100),
			Why:   "трафик перекошен в отдачу",
		})
	}

	// Имена, которых нет ни в одном списке, потому что их сгенерировали
	if v.RandomNameShare >= randomHeavy && v.RandomNameOwners >= randomOwnersMin && v.Owners >= randomOwnersSeen {
		out = append(out, Finding{
			Kind:  fedpb.AbuseKind_ABUSE_KIND_MALWARE,
			Count: uint32(v.RandomNameShare * 100),
			Why:   "имена доменов похожи на сгенерированные автоматом",
		})
	}

	// Сплошной голый адрес плюс россыпь чужих пиров
	if v.NoDomainShare >= bareHeavy && v.DistinctBarePeers >= 40 {
		out = append(out, Finding{
			Kind:  fedpb.AbuseKind_ABUSE_KIND_TORRENT,
			Count: v.DistinctBarePeers,
			Why:   "почти весь трафик на голые адреса, пиров много",
		})
	}

	// Свежие домены пачкой. Фишинг и кардинг живут на именах, заведённых пару
	// недель назад, и никакой список за ними не поспевает - зато реестр знает
	// дату всегда
	if v.FreshDomains >= freshDomainMin && v.FreshDomainShare >= freshDomainHeavy {
		out = append(out, Finding{
			Kind:  fedpb.AbuseKind_ABUSE_KIND_MALWARE,
			Count: uint32(v.FreshDomains),
			Why:   "почти все домены зарегистрированы на днях",
		})
	}

	if v.PortsTouched >= portScanPorts {
		out = append(out, Finding{
			Kind:  fedpb.AbuseKind_ABUSE_KIND_PORT_SCAN,
			Count: uint32(v.PortsTouched),
			Why:   "задето слишком много разных портов",
		})
	}

	return out
}
