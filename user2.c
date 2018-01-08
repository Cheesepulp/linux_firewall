#include <stddef.h>
#include <stdio.h>
#include <ctype.h>
#include <linux/types.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/un.h>
#include <fcntl.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <getopt.h>

#include "lwfw.h"


char *help=
"********************************command*************************************\n"
"* designed by HWL                                                         \n"
"* -S 打开防火墙						            \n"
"* -E 关闭防火墙                                                            \n"
"* -A 添加规则                                                              \n"
"*    如： -A --srcip 192.168.10.5 --srcport 80 --destip 10.10.10.10 --destport 10 --proto tcp --accept  \n"
"* -D 删除规则 如： -D 1 #删除第一条规则                                     \n"
"* -L 打印规则                                                              \n"
"* -def 设置默认策略 如：-def accept/drop		                    \n"
"* -log 记录日志						            \n"
"****************************************************************************\n";


int main(int argc,char **argv){

	int fmyipfilter = 0;
	int rc = 0;
	int option_index = 0;
	int c = 0;
	rule_node new_rule_node;
	new_rule_node.action = -1;
	int count = 0;
	int index = 0;
	char buff[2000];
	int i = 0;

	struct option long_options[] = 
{
	{"accept", no_argument, &new_rule_node.action, 0},
    {"drop", no_argument, &new_rule_node.action, 1},
    {"srcip", required_argument, 0, 's'},
    {"srcport", required_argument, 0, 'p'},
    {"destip", required_argument, 0, 't'},
    {"destport", required_argument, 0, 'q'},
    {"proto", required_argument, 0, 'c'},
    {0, 0, 0, 0}
 };
		

	fmyipfilter=open("/dev/lwfw2",O_RDWR);
	if(fmyipfilter<0)
	{
		printf("open /dev/lwfw2 failed\n");
		rc= -1;
		fmyipfilter=0;
		goto err;
	}

	if (argc == 1){
		printf("usage:%s\n",help);
		return 0;
	}
	else if (argc == 2){
		if(!strcmp(argv[1],"-S")){
			rc=ioctl(fmyipfilter,IOCTL_CMD_START,0);
			if(rc<0)
			{
				printf("防火墙开启失败!\n");
				goto err;
			}
			else
			{
				printf("防火墙开启成功!\n");
			}
		}
		else if(!strcmp(argv[1],"-E")){
			rc=ioctl(fmyipfilter,IOCTL_CMD_STOP ,0);
			if(rc<0)
			{
				printf("防火墙关闭失败!\n");
				goto err;
			}
			else
			{
				printf("防火墙关闭成功!\n");
			}

		}
		else if(!strcmp(argv[1],"-L")){
			FILE *f;
			f = fopen("rule.txt","w+");
			rc=ioctl(fmyipfilter,IOCTL_CMD_LIST,buff);
			if(rc<0)
			{
				printf("打印规则失败!\n");
				goto err;
			}
			else
			{
				i = 1;
				if (buff[0] == ACTION_ACCEPT)
				{
					printf("defualt action:accept\n");
					fprintf(f,"defualt action:accept\n");
				}
				else
				{
					printf("defualt action:drop\n");
					fprintf(f,"defualt action:drop\n");
				}
				printf("protocol\tsrcip\t\tsrcport\t  destip\tdestport\taction\n");
				fprintf(f,"protocol\tsrcip\t\tsrcport\t  destip\tdestport\taction\n");
				while(buff[i]!=-1)
				{
					printf("%c\t\t",buff[i]);
        			printf("%3d.%3d.%3d.%3d\t",(unsigned char)buff[i+1],(unsigned char)buff[i+2],(unsigned char)buff[i+3],(unsigned char)buff[i+4]);
					printf("%d\t",buff[i+5]);
        			printf("%3d.%3d.%3d.%3d\t",(unsigned char)buff[i+6],(unsigned char)buff[i+7],(unsigned char)buff[i+8],(unsigned char)buff[i+9]);
					printf("%d\t\t",buff[i+10]);
					if (buff[i+11] == ACTION_ACCEPT)
						printf("accept\n");
					else
						printf("drop\n");

					fprintf(f,"%c\t\t",buff[i]);
        			fprintf(f,"%3d.%3d.%3d.%3d\t",(unsigned char)buff[i+1],(unsigned char)buff[i+2],(unsigned char)buff[i+3],(unsigned char)buff[i+4]);
					fprintf(f,"%d\t",buff[i+5]);
        			fprintf(f,"%3d.%3d.%3d.%3d\t",(unsigned char)buff[i+6],(unsigned char)buff[i+7],(unsigned char)buff[i+8],(unsigned char)buff[i+9]);
					fprintf(f,"%d\t\t",buff[i+10]);
					if (buff[i+11] == ACTION_ACCEPT)
						fprintf(f,"accept\n");
					else
						fprintf(f,"drop\n");
					i = i+12;
				}
			}
			fclose(f);
			system("gedit ./rule.txt");
		}
		else if(!strcmp(argv[1],"-log"))
		{
	   		FILE *f;
    		f=fopen("log.txt","w+");
    		FILE *fs=popen("dmesg |grep hwl","r");
    		char s[128]="";
    		while(fgets(s,sizeof(s),fs)!=NULL)
   		    {
      			fputs(s,f);
    	    }
    		fclose(f);
    		fclose(fs);
    		system("gedit ./log.txt");
		}

	}
	else if(argc > 2){
		if(!strcmp(argv[1],"-A")){
			count = 0;
			while(1){
        		c = getopt_long(argc, argv, "As:p:t:q:c:a:", long_options, &option_index);
        		if(c==-1)
        			break;
        		switch(c)
        		{
        			case 's':
              		new_rule_node.srcip = inet_addr(optarg);  //src ip
              		count ++;
              		printf("%s\t",optarg);
              		break; 
            		case 'p':
              		new_rule_node.srcport = atoi(optarg); 
              		count ++;
              		printf("%s\t",optarg);
              		break;
              		case 't':
              		new_rule_node.destip = inet_addr(optarg);
              		count ++;
              		printf("%s\t",optarg);
              		break;
              		case 'q':
              		new_rule_node.destport = atoi(optarg);
              		count ++;
              		printf("%s\t",optarg);
              		break;
              		case 'c':
              		new_rule_node.proto = *optarg;
              		count ++;
              		printf("%s\t",optarg);
              		break;
 /*
              		case 'a':
              		new_rule_node.action = *optarg;
              		count ++;
              		printf("%s\t",optarg);
              		break;
 */
              		case 'A':
              		break;
              		case 0:
              		count++;
              		break;
              		default:
              		abort();
        		}

			}
			if(count!=6){
				printf("规则格式不正确\n");
			}
			else{
				rc=ioctl(fmyipfilter,IOCTL_CMD_ADDRULE,&new_rule_node);
				printf("添加过滤规则成功\n");
			}
		}
		else if(!strcmp(argv[1],"-D")){
			if(argc!=3)
			{
				printf("-D后面需要输入规则序号！\n");
				goto err;
			}
			index = atoi(argv[2]);
			if(  index>= 0 )
			{
				rc=ioctl(fmyipfilter,IOCTL_CMD_DELRULE,&index);
				if(rc<0)
				{
					printf("删除规则失败\n");
					goto err;
				}
			}
			else 
			{
				printf("删除规则失败\n");
				goto err;
			}	
		}
		else if(!strcmp(argv[1],"-def")){
			if(argc!=3)
			{
				goto err;
			}
			if( !strcmp(argv[2],"accept") )
			{
				index = ACTION_ACCEPT;
				rc=ioctl(fmyipfilter,IOCTL_CMD_SETDEFAULT,&index);
				if(rc<0)
				{
					printf("设置默认规则失败\n");
					goto err;
				}
				else
				{
					printf("设置默认规则成功\n");
				}
			}
			else if(!strcmp(argv[2],"drop"))
			{
				index = ACTION_DROP;
				rc=ioctl(fmyipfilter,IOCTL_CMD_SETDEFAULT,&index);
				if(rc<0)
				{
					printf("设置默认规则失败\n");
					goto err;
				}
				else
				{
					printf("设置默认规则成功\n");
				}	
			}
			else 
			{
			goto err;
			}	
		}
		else if(!strcmp(argv[1],"-C"))
		{
			rc=ioctl(fmyipfilter,IOCTL_CMD_CLEAR ,0);
			if(rc<0)
			{
				printf("清空规则失败!\n");
				goto err;
			}
            else
			{
				printf("清空规则成功!\n");
			}
		}

	}
	err:
	if(fmyipfilter){
		close(fmyipfilter);
	}
	return 0;
}

