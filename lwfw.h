#ifndef _LWFW_INCLUDE_
#define _LWFW_INCLUDE_
//ioctl交互命令
#define IOCTL_CMD_START 1   //开启过滤
#define IOCTL_CMD_STOP  8	//关闭过滤
#define IOCTL_CMD_ADDRULE 3 //添加规则
#define IOCTL_CMD_DELRULE 4 //删除规则
#define IOCTL_CMD_CLEAR 5   //清空规则
#define IOCTL_CMD_LIST 6	//打印规则
#define IOCTL_CMD_SETDEFAULT 7 //设置默认策略

#define ACTION_ACCEPT 0 	//接收报文
#define ACTION_DROP   1     //丢弃报文

//内核返回状态
#define MSTATUS_SUCCESS 0  //执行成功
#define MSTATUS_DEL_ERR -1 //删除失败
#define MSTATUS_ADD_ERR -2 //添加失败
#define MSTATUS_CP_ERR  -3 //从用户态拷贝数据失败

//规则链节点
typedef struct rule_node {
	__be32 destip, srcip; //源和目的IP
	__be16 destport, srcport; //源和目的端口
	int action;//
    unsigned char proto;
	struct rule_node *next;
	}rule_node,*prule_node;

//保存报文TCP相关字段，用于和规则进行匹配	
typedef struct pack_info{
	__be32 destip, srcip;
	__be16 destport, srcport;
	}pack_info, *ppack_info;
#endif
