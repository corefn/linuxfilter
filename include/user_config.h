/*
 * Name:	user_config.h
 * Author:	Feng Wei
 * Date:	Nov 17, 2014
 *
 * Description: mainly to configure userspace, including:
 *
 * 	1.	initialize netlink socket, and send some config to kernel;
 *
 * 	2.	initialize mysql config, and fetch userconfig ,appconfig, etc ;
 *
 * 	3.	parse  signature.xml file;
 *
 */

#ifndef USER_CONFIG_H
#define USER_CONFIG_H

#include <linux/netlink.h>

#define COMMAND_NAME_LEN		16
#define PARAMETER_LEN			128
#define MAX_PAYLOAD_LEN			160
#define SIG_LEN					14
#define	TCP_PROTO				6
#define UDP_PROTO				17

/*
 * represent filter information to kernel
 */
typedef struct FilterMsg {
	struct nlmsghdr		hdr;
	unsigned char 		data[MAX_PAYLOAD_LEN];	/* store struct UserCommand object*/
} FilterMsg;

/*
 * represent user commands that include:
 *
 * 	1.	FEATURE_CMD: load protocol feature from signature.xml;
 *
 * 	2.	USER_CMD: fetch user information from mysql;
 *
 * 	3.	APPCONFIG_CMD: fetch application information from mysql;
 *
 * 	4.	POLICY_CMD: fetch control policy form mysql.
 */
typedef struct UserCommand {
	char			main_cmd_name[COMMAND_NAME_LEN];
	char			sub_cmd_name[COMMAND_NAME_LEN];
	unsigned char	param[PARAMETER_LEN]; /* sotre XXXpolicy */
} UserCommand;

/*
 * represent user information from mysql table
 */
typedef struct UserConfig {
	unsigned int		ip;
	int			level;
} UserConfig;

/*
 * represent some protocols' features
 */
typedef struct FeatureConfig {
	int		app_id;
	unsigned char	sigs[SIG_LEN];
	unsigned char	mask[SIG_LEN];
	unsigned char	protocol;				/* represent transport layer protocol */
} FeatureConfig;

/*
 * represent application information from mysql table
 */
typedef struct AppConfig {
	int		app_config_id;
	int		app_id;
	int		band_width;
	int		begin_time;
	int		end_time;
} AppConfig;

/*
 * represent control policy 
 */
typedef struct PolicyConfig {
	int		level;
	int		app_config_id;
} PolicyConfig;

#endif	/*USER_CONFIG_H*/
