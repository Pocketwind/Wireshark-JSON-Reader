#include <iostream>
#include <stdint.h> 

// 타임 스탬프 변수형
typedef uint32_t timestamp_t; //seconds

// 데이트타임 구조체
typedef struct {
	uint16_t    year;
	uint8_t     month;
	uint8_t     day;
	uint8_t     hour;
	uint8_t     minute;
	uint8_t     second;
	uint8_t     week;
	uint8_t     weekday;
} datetime_t;

// 1일을 초로
#define ONE_DAY                  (1*60*60*24) 
// UTC 시작 시간
#define UTC_TIME_WEEKDAY_OFFSET (4) /* 1970,1,1은 목요일이기때문에 */

//날짜                    x, 1월, 2월 ..... 11월, 12월
uint8_t month_days[13] = { 0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

//타임 스탬프를 기준으로 요일 얻기
uint8_t timestamp_to_weekday(timestamp_t timestamp_sec)
{
	uint8_t result = (timestamp_sec / ONE_DAY + UTC_TIME_WEEKDAY_OFFSET) % 7;
	if (result == 0) {
		result = 7;
	}
	return result;
}

//윤달 확인
int is_leap_year(uint16_t year)
{
	if (year % 4 == 0 && ((year % 100) != 0) || ((year % 400) == 0)) {
		return true;
	}
	else
		return false;
}

//utc 타임 스탬프를 날짜로 변환
void utc_timestamp_to_date(timestamp_t timestamp, datetime_t* datetime)
{
	uint8_t  month;
	uint32_t days;
	uint16_t days_in_year;
	uint16_t year;
	timestamp_t second_in_day;

	// 시/분/초 계산
	second_in_day = timestamp % ONE_DAY;

	//초
	datetime->second = second_in_day % 60;

	//분
	second_in_day /= 60;
	datetime->minute = second_in_day % 60;

	//시
	second_in_day /= 60;
	datetime->hour = second_in_day % 24;


	//1970-1-1 0:0:0부터 현재까지 총 일수
	days = timestamp / ONE_DAY;

	//days를 계속 차감하면서 해당 년도 계산
	for (year = 1970; year <= 2200; year++) {
		if (is_leap_year(year))
			days_in_year = 366;
		else
			days_in_year = 365;

		if (days >= days_in_year)
			days -= days_in_year;
		else
			break;
	}

	//년
	datetime->year = year;

	//요일 
	datetime->weekday = timestamp_to_weekday(timestamp);

	//해당 년도 1월 1일을 기준으로 지금까지의 주(week) 계산 
	datetime->week = (days + 11 - datetime->weekday) / 7;

	//월 계산하기
	if (is_leap_year(datetime->year)) //윤달의 경우 2월이 29일이다.
		month_days[2] = 29;
	else
		month_days[2] = 28;

	//년도와 마찬가지로 일에서 계속 차감해서 찾는다.
	for (month = 1; month <= 12; month++) {
		if (days >= month_days[month])
			days -= month_days[month];
		else
			break;
	}
	datetime->month = month;
	datetime->day = days + 1;
}

