# Secure Access Monitoring

## O projekcie
To jest moj projekt o bezpiecznym dostepie do aplikacji. Zalezalalo mi na tym, zeby nie konczyc na samym logowaniu, tylko pokazac tez to, co dzieje sie pozniej: bledne proby podania hasla, blokade konta, rozpoznawanie nowego urzadzenia i ocene bardziej wrazliwych akcji.

Projekt nie udaje pelnego systemu produkcyjnego. To raczej mala aplikacja pokazujaca kilka konkretnych mechanizmow security w jednym miejscu i w czytelnym przeplywie.

## Co mozna tu sprawdzic
- rejestracje uzytkownika
- hashowanie hasla przy uzyciu BCrypt
- logowanie przez formularz Spring Security
- licznik nieudanych prob i blokade konta
- zapamietywanie znanego urzadzenia oraz znanego zrodla zadania
- ocene ryzyka dla wybranej, chronionej akcji
- logi bezpieczenstwa przypisane do zalogowanego uzytkownika

## Jak to dziala
Najpierw tworze konto i loguje sie do aplikacji. Po udanym logowaniu system zapamietuje browser i zrodlo zadania. Przy kolejnych krokach porownuje aktualny kontekst z tym, co bylo juz widziane dla danego konta.

Jesli ponownie potwierdzam haslo, aplikacja:
- sprawdza zgodnosc hasla
- zlicza bledne proby
- blokuje konto po przekroczeniu limitu
- zapisuje wszystko w logach

Jesli uruchamiam chroniona akcje, wybieram tylko jej typ. Reszte ocenia backend:
- jak wrazliwa jest sama akcja
- czy browser byl juz znany
- czy zrodlo bylo juz znane

Na tej podstawie system zwraca wynik i poziom ryzyka.

## Technologie
- Java 17
- Spring Boot 3
- Spring Web
- Spring Data JPA
- Spring Security
- H2 Database
- HTML, CSS, JavaScript

## Jak uruchomic
1. Otworz projekt w IntelliJ IDEA.
2. Uruchom klase `banksecurity.SecureAccessMonitoringApplication`.
3. Wejdz na `http://localhost:8081/`.

## Co jest na stronie glownej
Na stronie glownej moge:
- zalozyc konto
- przejsc do logowania
- sprawdzic potwierdzenie hasla dla aktywnej sesji
- uruchomic kontrole chronionej akcji
- podejrzec logi bezpieczenstwa
- skorzystac z kilku gotowych scenariuszy

## Krotkie podsumowanie
Najwazniejsze w tym projekcie jest to, ze uzytkownik nie wpisuje recznie zagrozen. Wykonuje zwykle akcje, a aplikacja sama probuje ocenic, czy dany kontekst wyglada znajomo, czy wymaga wiekszej ostroznosci.
