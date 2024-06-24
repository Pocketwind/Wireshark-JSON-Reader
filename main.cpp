#pragma warning(disable:4996)

#include <iostream>
#include<fstream>
#include<string>
#include<vector>
#include <stdint.h> 
#include<regex>
#include<math.h>
#include"rapidjson/document.h"
#include"rapidjson/filereadstream.h"
#include"rapidjson/writer.h"
#include"rapidjson/stringbuffer.h"

using namespace std;
using namespace rapidjson;


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

class Packet
{
public:
	string servername, source_addr, dest_addr, frame_time;
	double time;
	int year, month, day, hour, minute, second, milisec;
	int packet_n;
	Packet(int n, double t, string name, string src, string dest, string frame_time)
	{
		packet_n = n;
		this->frame_time = regex_replace(frame_time, regex(" 대한민국 표준시"), "");
		source_addr = src;
		dest_addr = dest;
		double d = 0.0;
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
		milisec = modf(t, &d);
	}
	string DateToString()
	{
		return to_string(year) + "/" + to_string(month) + "/" + to_string(day) + " " +
			to_string(hour) + ":" + to_string(minute) + ":" + to_string(second);//to_string(milisec);
	}
};

int main(int argc, char *argv[])
{
	Document doc;
	FILE* file = fopen(argv[1], "r");
	if (file == NULL)
	{
		cout << "파일X";
		return 0;
	}

	char buffer[10000];
	FileReadStream inputStream(file, buffer, sizeof(buffer));
	vector<Packet> packet;


	doc.ParseStream(inputStream);

	StringBuffer stringbuffer;
	Writer<StringBuffer> writer(stringbuffer);
	doc.Accept(writer);
	
	string jsonString = stringbuffer.GetString();
	jsonString = regex_replace(jsonString, regex("len=\\d\\d\\d|len=\\d\\d|len=\\d"), "");
	doc.Parse(jsonString.c_str());
	

	for (int i = 0; i < doc.Size(); ++i)
	{
		int packet_n = i + 1;
		bool print = false;
		string time, SNI, source_addr, dest_addr, frame_time;
		Value& root = doc[i];
		if (root.IsString())
			continue;
		if (root.HasMember("_source"))
		{
			Value& source = root["_source"];
			if (source.IsString())
				continue;
			if(source.HasMember("layers"))
			{ 
				Value& layers = source["layers"];
				if (layers.IsString())
					continue;
				time = layers["frame"]["frame.time_epoch"].GetString();
				frame_time = layers["frame"]["frame.time"].GetString();
				if (layers.HasMember("ip"))
				{
					Value& ip = layers["ip"];
					source_addr = ip["ip.src"].GetString();
					dest_addr = ip["ip.dst"].GetString();
				}
				if (layers.HasMember("tls"))
				{
					Value& tls = layers["tls"];
					if (tls.IsString())
						continue;
					if (tls.HasMember("tls.record"))
					{
						Value& tls_record = tls["tls.record"];
						if (tls_record.IsString())
							continue;
						if (tls_record.HasMember("tls.handshake"))
						{
							Value& tls_handshake = tls_record["tls.handshake"];
							if(tls_handshake.IsString())
								continue;
							if (tls_handshake.HasMember("Extension: server_name ()"))
							{
								Value& extension_servername = tls_handshake["Extension: server_name ()"];
								if (extension_servername.IsString())
									continue;
								if (extension_servername.HasMember("Server Name Indication extension"))
								{
									Value& server_name = extension_servername["Server Name Indication extension"]["tls.handshake.extensions_server_name"];
									SNI = server_name.GetString();
									print = true;
								}
							}
						}
					}
				}
			}
		}
		if (print)
			packet.push_back(Packet(packet_n, stod(time), SNI, source_addr, dest_addr, frame_time));
	}

	for (int i = 0; i < packet.size(); ++i)
	{
		cout << packet[i].DateToString() << " | " << packet[i].frame_time << " | " << packet[i].servername << " | " << packet[i].source_addr << " | " << packet[i].dest_addr << endl;
	}

	string output_filename = regex_replace(argv[1], regex("json"), "csv");
	ofstream file_out(output_filename);
	file_out << "sep=;" << endl;
	file_out << "Packet #;UNIX Time;SNI;Source;Destination;frame.time" << endl;
	for (int i = 0; i < packet.size(); ++i)
	{
		if (packet[i].servername.compare(""))
			file_out << packet[i].packet_n << ";" << "=\"" << packet[i].DateToString() << "\"" << ";" << packet[i].servername << ";" << packet[i].source_addr << ";" << packet[i].dest_addr << ";" << "=\"" << packet[i].frame_time << "\"" << endl;
	}
	file_out.close();
	fclose(file);
	return 0;
}
