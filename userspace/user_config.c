#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <mysql/mysql.h>
#include "../include/user_config.h"

#define INIT_SYS				1
#define	USER_CONFIG				2
#define FEATURE_CONFIG			3
#define APP_CONFIG				4
#define POLICY_CONFIG			5
#define NETLINK_LINUX_FILTER	31		/*Unkonwn*/

/*
 * user commnds from console command line
 */
const char *INIT_CMD		=	"init";
const char *USER_CMD		=	"user";
const char *FEATURE_CMD		=	"feature";
const char *APP_CMD			=	"app";
const char *POLICY_CMD		=	"policy";

/*
 * mysql databse name, username, passwd and some SQLs
 */
const char *DATA_BASE	=	"filter_db";
const char *USER_NAME	=	"root";
const char *USER_PASS	=	"123456";

const char *USER_INFO	=	"select * from user_info";
const char *APP_INFO	=	"select * from app_info";
const char *POLICY_INFO	=	"select * from policy_info";
const char *XML_FILE	=	"/home/feng/linuxfilter/feature/signature.xml";

/*
 * initialize and bind netlink socket
 */
static int InitSocket(struct sockaddr_nl *p_src_addr)
{
	int sock;

	p_src_addr->nl_family	= AF_NETLINK;
	p_src_addr->nl_pad		= 0;
	p_src_addr->nl_pid		= getpid();
	p_src_addr->nl_groups	= 0;

	if ((sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_FIREWALL)) < 0) 
	{
		perror("socket error");
		return -1;
	}

	if (bind(sock, (struct sockaddr *)p_src_addr, sizeof(struct sockaddr_nl)) < 0) 
	{
		perror("bind error");
		return -1;
	}

	return sock;
}

/*
 * initialize mysql connection
 */
static MYSQL* InitMysql()
{
	MYSQL *mysql;

	if ((mysql = mysql_init(NULL)) == NULL) 
	{
		perror("mysql initialize error");
		return NULL;
	}

	if (mysql_real_connect(mysql, "localhost", USER_NAME, USER_PASS, DATA_BASE, 0, NULL, 0) == NULL) 
	{
		perror("mysql_real_connect error");
		return NULL;
	}

	return mysql;
}

/*
 * map command strings to numbers
 */
static int ParseCommand(char *argv[])
{
	if (strcmp(argv[1], INIT_CMD) == 0) 
	{
		return INIT_SYS;
	} 
	else if (strcmp(argv[1], USER_CMD) == 0) 
	{
		return USER_CONFIG;
	} 
	else if (strcmp(argv[1], FEATURE_CMD) == 0) 
	{
		return FEATURE_CONFIG;
	} 
	else if (strcmp(argv[1], APP_CMD) == 0) 
	{
		return APP_CONFIG;
	} 
	else if (strcmp(argv[1], POLICY_CMD) == 0) 
	{
		return POLICY_CONFIG;
	}

	return -1;
}

/*
 * configure user, app and policy based on type
 */
static void ProcessRow(MYSQL_ROW row, void *structure, int type)
{
	UserConfig		*my_user_config;
	AppConfig		*my_app_config;
	PolicyConfig	*my_policy_config;

	switch (type)
	{
		case USER_CONFIG:
			my_user_config			=	(UserConfig *)structure;
			inet_aton(row[0], (struct in_addr *)&(my_user_config->ip));
			my_user_config->level	=	strtol(row[1], NULL, 10);
			break;
		case APP_CONFIG:
			my_app_config					=	(AppConfig *)structure;
			my_app_config->app_config_id	=	strtol(row[0], NULL, 10);
			my_app_config->app_id			=	strtol(row[1], NULL, 10);
			my_app_config->band_width		=	strtol(row[2], NULL, 10);
			my_app_config->begin_time		=	strtol(row[3], NULL, 10);
			my_app_config->end_time			=	strtol(row[4], NULL, 10);
			break;
		case POLICY_CONFIG:
			my_policy_config				=	(PolicyConfig *)structure;
			my_policy_config->level			=	strtol(row[0], NULL, 10);
			my_policy_config->app_config_id	=	strtol(row[1], NULL, 10);
			break;
		default:
			perror("Unknown config");
			break;
	}
}

/*
 * send UserConfig, AppConfig or PolicyConfig to kernel
 */
static void CommonConfig(MYSQL *mysql, int sock, 
		struct sockaddr_nl *p_dst_addr, void *common_config, 
		const char *sql_str, const char *common_cmd, int type)
{
	MYSQL_RES	*result;
	MYSQL_ROW	row;
	UserCommand	command;
	FilterMsg	msg;

	mysql_query(mysql, sql_str);
	result	=	mysql_store_result(mysql);

	msg.hdr.nlmsg_len	=	sizeof(msg);
	msg.hdr.nlmsg_type	=	0;
	msg.hdr.nlmsg_flags	=	0;
	msg.hdr.nlmsg_seq	=	0;
	msg.hdr.nlmsg_pid	=	getpid();

	strcpy(command.main_cmd_name, common_cmd);
	while ((row = mysql_fetch_row(result)) != NULL) 
	{
		ProcessRow(row, common_config, type);
		memcpy(command.param, common_config, sizeof((*common_config)));
		memcpy(msg.data, &command, sizeof(command));

		sendto(sock, &msg, sizeof(msg),
				0, (struct sockaddr *)p_dst_addr, sizeof(struct sockaddr_nl));
	}
}

/******************************************************************
 * some functions to parse signature.xml
 *****************************************************************/
#define APPID_LEN		32
#define LINE_BUF_LEN	128	

/*
 * read a line from signature.xml
 */
static int ReadLine(FILE *fp, char *buf)
{
	char	c;
	int		i = 0;

	while ((c = getc(fp)) != EOF && c != '\n')
	{
		if ( c != '\r' && c != '\t')
		{
			buf[i++] = c;
		}
	}
	buf[i] = '\0';

	if (c == EOF)
	{
		return EOF;
	}

	return i;
}
/*
 * judge whether buffer contains app or feature
 */
static int AppOrFeatureStart(char *buf, char *name, int len)
{
	int i = 0;

	while (buf[i++] == ' ' || buf[i++] == '\t');

	if (strncmp(buf + i, name, len) == 0)
	{
		return 1;
	}
	else
	{
		return 0;
	}

	return -1;
}

/*
 * get the app id from buffer
 */
static int GetAppID(char *buf, int len)
{
	int		i, j ,k;
	char	app_id[APPID_LEN];

	for (i = 0; i + 2 < len; i++)
	{
		if (buf[i] == 'i' 
				&& buf[i + 1] == 'd'
				&& buf[i + 2] == '=')
		{
			j = i + 4;
			k = 0;
			while (buf[j] != '\"') 
			{
				app_id[k++] = buf[j++];
			}
			app_id[k] = '\0';

			return atoi(app_id); 
		}
	}

	return -1;
}

/*
 * get some applications feature from signature.xml
 */
static void GetFeature(FILE *fp, FeatureConfig *p_feature)
{
	char buf[LINE_BUF_LEN];
	int i = 0;
	int j = 0;

	ReadLine(fp, buf);
	while (buf[i++] == ' ' || buf[i] == '\t');
	while (buf[i++] != '>');

	if (strncmp(buf + i, "tcp", 3) == 0) 
	{
		p_feature->protocol = TCP_PROTO;
	}
	else if (strncmp(buf + i, "udp", 3) == 0) 
	{
		p_feature->protocol = UDP_PROTO;
	}

	ReadLine(fp, buf);
	i = 0;
	while (buf[i++] == ' ' || buf[i] == '\t');
	while (buf[i++] != '>');
	for (j = 0; j < SIG_LEN; ++j)
	{
		p_feature->sigs[j] = strtol(buf + i, NULL, 16);
		i += 3;
	}

	ReadLine(fp, buf);
	i = 0;
	while (buf[i++] == ' ' || buf[i] == '\t');
	while (buf[i++] != '>');
	for (j = 0; j < SIG_LEN; ++j)
	{
		p_feature->mask[j] = strtol(buf + i, NULL, 16);
		i += 3;
	}

	ReadLine(fp, buf);
}
/*
 * send protocol feature to kernel
 */
static void LoadFeature(int sock, struct sockaddr_nl *p_dst_addr)
{
	FILE *file;
	char buf[LINE_BUF_LEN];
	int i, len;
	int app_id;
	UserCommand command;
	FeatureConfig my_feature_config;
	FilterMsg msg;

	if ((file = fopen(XML_FILE, "r")) == NULL)
	{
		perror("fopen error");
		return ;
	}

	msg.hdr.nlmsg_len	=	sizeof(msg);
	msg.hdr.nlmsg_type	=	0;
	msg.hdr.nlmsg_flags	=	0;
	msg.hdr.nlmsg_seq	=	0;
	msg.hdr.nlmsg_pid	=	getpid();

	strcmp(command.main_cmd_name, FEATURE_CMD);
	while ((len = ReadLine(file, buf)) != EOF)
	{
		if (AppOrFeatureStart(buf, "app", 3))
		{
			app_id	=	GetAppID(buf, len);
			len		=	ReadLine(file, buf);
			while (AppOrFeatureStart(buf, "feature", 7)) 
			{
				my_feature_config.app_id = app_id;
				GetFeature(file, &my_feature_config);
				memcpy(command.param, &my_feature_config, sizeof(my_feature_config));
				memcpy(msg.data, &command, sizeof(command));

				sendto(sock, &msg, sizeof(msg),
						0, (struct sockaddr *)p_dst_addr,
						sizeof(struct sockaddr_nl));

				len = ReadLine(file, buf);
			}
		}
	}
	fclose(file);
}

static ConfigFilter(char *argv[], MYSQL *conn, int sock,
		struct sockaddr_nl *p_dst_addr)
{
	int command;
	UserConfig my_user_config;
	AppConfig my_app_config;
	PolicyConfig my_policy_config;

	command = ParseCommand(argv);
	switch (command)
	{
		case USER_CONFIG:
			CommonConfig(conn, sock, p_dst_addr, (void *)&my_user_config,
					USER_INFO, USER_CMD, USER_CONFIG);
			break;
		case APP_CONFIG:
			CommonConfig(conn, sock, p_dst_addr, (void *)&my_app_config,
					APP_INFO, APP_CMD, APP_CONFIG);
			break;
		case POLICY_CONFIG:
			CommonConfig(conn, sock, p_dst_addr, (void *)&my_policy_config,
					POLICY_INFO, POLICY_CMD, POLICY_CONFIG);
			break;
		case FEATURE_CONFIG:
			LoadFeature(sock, p_dst_addr);
			break;
		default:
			perror("unknown command");
			break;
	}
}

int main(int argc, char *argv[])
{
	int sock;
	MYSQL *mysql;
	struct sockaddr_nl src_addr;
	struct sockaddr_nl dst_addr;

	if ((sock = InitSocket(&src_addr)) < 0)
	{
		perror("InitSocket error");
		return -1;
	}

	if ((mysql = InitMysql()) == NULL)
	{
		perror("InitMysql error");
		return -1;
	}

	dst_addr.nl_family	=	AF_NETLINK;
	dst_addr.nl_pad		=	0;
	dst_addr.nl_pid		=	0;
	dst_addr.nl_groups	=	0;

	ConfigFilter(argv, mysql, sock, &dst_addr);

	close(sock);
	mysql_close(mysql);

	return 0;
}
