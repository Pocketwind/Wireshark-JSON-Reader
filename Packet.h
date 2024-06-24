#include<string>
#include<iostream>
#include"TimeConverter.h"

using namespace std;

class Packet
{
public:
	string servername;
	double time;
	int year, month, day, hour, minute, second;
	Packet(double t, string name)
	{
		timestamp_t unix = t;
		datetime_t date;
		utc_timestamp_to_date(unix, &date);
		servername = name;
		this->time = time;
		year = date.year;
		month = date.month;
		day = date.day;
		hour = date.hour;
		minute = date.minute;
		second = date.second;
	}
	string DateToString()
	{
		string date;
		date = to_string(year) + "년 " + to_string(month) + "월 " + to_string(day) + "일" + to_string(hour) + "시 " + to_string(minute) + "분 " + to_string(second) + "초";
		return date;
	}
};