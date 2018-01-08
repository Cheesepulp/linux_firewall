#include <linux/module.h>	/* Needed by all modules */
#include <linux/moduleparam.h>
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/init.h>		/* Needed for the macros */
#include <linux/string.h>	/* Needed for memset */
#include <linux/miscdevice.h>
#include <linux/ctype.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/udp.h>
#include "linux/fs.h"
#include "asm/uaccess.h"
#include <linux/cdev.h>           /// struct cdev

#include "lwfw.h"

static int rule_add(rule_node *phead,rule_node *pnew_node);
static int rule_del(rule_node *phead,int index);
static int rule_list(char *buff);
static int check_rule(rule_node *pcurrent_rule,pack_info *pcurrent_info);
static int start_filter(void);
static int stop_filter(void);
static int myfilter_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
static int rule_clear(rule_node *phead);

static int __init init_myipfilter_module(void);
static void __exit cleanup_myipfilter_module(void);

static struct nf_hook_ops hook1;
static struct nf_hook_ops hook2;

struct cdev cdev_m;
static int major = 0; 

rule_node *phead_rule = NULL;
int default_action = ACTION_ACCEPT;

static int hooked = 0;

static struct file_operations myfilter_fops = {
	.owner =	THIS_MODULE,
	.unlocked_ioctl =	myfilter_ioctl,
};

static  struct miscdevice vms_miscdevice = {
	.minor = 248,
	.name = "lwfw2", //设备名
	.fops = &myfilter_fops, //驱动对应的file_operations结构
};

static char buf[2000];

#ifdef DEBUG
#define TRACE_ENTRY printk(KERN_CRIT "Entering %s\n", __func__)
#define TRACE_EXIT  printk(KERN_CRIT "Exiting %s\n", __func__)
#define DPRINTK( x, args... ) printk(KERN_CRIT "%s: line %d: " x, __FUNCTION__ , __LINE__ , ## args ); 
#else
#define TRACE_ENTRY do {} while (0)
#define TRACE_EXIT  do {} while (0)
#define DPRINTK( x, args... )  do {} while (0)
#endif //DEBUG

#define TRACE_ERROR printk(KERN_CRIT "Exiting (ERROR) %s\n", __func__)

/*
 * 检查当前的报文相关特征是否匹配当前规则
 */
static int check_rule(rule_node *pcurrent_rule,pack_info *pcurrent_info){
	//规则中相应的字段为0表示不对其做限制，继续匹配下一字段
	if (pcurrent_rule->srcip != 0 && pcurrent_rule->srcip != pcurrent_info->srcip)
		return 0;
	if (pcurrent_rule->srcport != 0 && pcurrent_rule->srcport != pcurrent_info->srcport)
		return 0;
	if (pcurrent_rule->destip != 0 && pcurrent_rule->destip != pcurrent_info->destip)
		return 0;
	if (pcurrent_rule->destport != 0 && pcurrent_rule->destport != pcurrent_info->destport)
		return 0;

	return 1;
}

unsigned int lwfw_hookfn(unsigned int hooknum,
                           struct sk_buff *skb,
                           const struct net_device *in,
                           const struct net_device *out,
                           int (*okfn)(struct sk_buff *))
{
	struct sk_buff *sb = skb;
	struct iphdr *piph = NULL;
	struct tcphdr *ptcph = NULL;
	struct udphdr *pudph = NULL;
	pack_info pack_info1;
	rule_node *ph = phead_rule->next;

	piph = ip_hdr(sb);
	//static char buf[1000];
	

//tcp
	if(piph->protocol == IPPROTO_TCP)
	{
		ptcph = (void *)piph + piph->ihl * 4;
		pack_info1.srcip = piph->saddr;
		pack_info1.destip = piph->daddr;
		pack_info1.srcport = ntohs(ptcph->source);
		pack_info1.destport = ntohs(ptcph->dest);
		while (ph != NULL)
		{
			if (check_rule(ph,&pack_info1)&&(ph->proto == 't'||ph->proto == 'o'))
			{//命中规则
				printk("success\n");      
				printk("<hwl>pro :%c\t",ph->proto);
				printk("<hwl>S: %d.%d.%d.%d\t",*((unsigned char *)&pack_info1.srcip),*((unsigned char *)&pack_info1.srcip+1),*((unsigned char *)&pack_info1.srcip+2),*((unsigned char *)&pack_info1.srcip+3));
				printk("<hwl>D: %d.%d.%d.%d\t",*((unsigned char *)&pack_info1.destip),*((unsigned char *)&pack_info1.destip+1),*((unsigned char *)&pack_info1.destip+2),*((unsigned char *)&pack_info1.destip+3));
				printk("<hwl>sp:%d\t",pack_info1.srcport);
				printk("<hwl>dp:%d\t",pack_info1.destport);
	        	if (ph->action == ACTION_ACCEPT)
		    	{
					printk("<hwl>accept\n");
					return NF_ACCEPT;
		    	}
		    	else
		   		{
			  		printk("<hwl>drop\n");
			  		return NF_DROP;
		   		}
		    }
		    else//继续匹配下一条
				ph = ph->next;
		}
		//无匹配 按默认策略
		if (default_action == ACTION_ACCEPT)
			return NF_ACCEPT;
		else
			return NF_DROP;
	}
//udp
	else if(piph->protocol == IPPROTO_UDP)
	{
		pudph = (void *)piph + piph->ihl * 4;
		pack_info1.srcip = piph->saddr;
		pack_info1.destip = piph->daddr;
		pack_info1.srcport = ntohs(pudph->source);
		pack_info1.destport = ntohs(pudph->dest);
		while (ph != NULL)
		{
			if (check_rule(ph,&pack_info1)&&(ph->proto == 'u'||ph->proto == 'o'))
			{//命中规则
				printk("success\n");      
				printk("<hwl>pro :%c\t",ph->proto);
				printk("<hwl>S: %d.%d.%d.%d\t",*((unsigned char *)&pack_info1.srcip),*((unsigned char *)&pack_info1.srcip+1),*((unsigned char *)&pack_info1.srcip+2),*((unsigned char *)&pack_info1.srcip+3));
				printk("<hwl>D: %d.%d.%d.%d\t",*((unsigned char *)&pack_info1.destip),*((unsigned char *)&pack_info1.destip+1),*((unsigned char *)&pack_info1.destip+2),*((unsigned char *)&pack_info1.destip+3));
				printk("<hwl>sp:%d\t",pack_info1.srcport);
				printk("<hwl>dp:%d\t",pack_info1.destport);
	        	if (ph->action == ACTION_ACCEPT)
		    	{
					printk("<hwl>accept\n");
					return NF_ACCEPT;
		    	}
		    	else
		   		{
			  		printk("<hwl>drop\n");
			  		return NF_DROP;
		   		}
		    }
		    else//继续匹配下一条
				ph = ph->next;
		}
		//无匹配 按默认策略
		if (default_action == ACTION_ACCEPT)
			return NF_ACCEPT;
		else
			return NF_DROP;
	}
//icmp
	if(piph->protocol == IPPROTO_ICMP)
	{
		pack_info1.srcip = piph->saddr;
		pack_info1.destip = piph->daddr;
		pack_info1.srcport = ntohs(0);
		pack_info1.destport = ntohs(0);
		while (ph != NULL)
		{
			if (check_rule(ph,&pack_info1)&&(ph->proto == 'i'||ph->proto == 'o'))
			{//命中规则
				printk("success\n");      
				printk("<hwl>pro :%c\t",ph->proto);
				printk("<hwl>S: %d.%d.%d.%d\t",*((unsigned char *)&pack_info1.srcip),*((unsigned char *)&pack_info1.srcip+1),*((unsigned char *)&pack_info1.srcip+2),*((unsigned char *)&pack_info1.srcip+3));
				printk("<hwl>D: %d.%d.%d.%d\t",*((unsigned char *)&pack_info1.destip),*((unsigned char *)&pack_info1.destip+1),*((unsigned char *)&pack_info1.destip+2),*((unsigned char *)&pack_info1.destip+3));
				printk("<hwl>sp:%d\t",pack_info1.srcport);
				printk("<hwl>dp:%d\t",pack_info1.destport);
	        	if (ph->action == ACTION_ACCEPT)
		    	{
					printk("<hwl>accept\n");
					return NF_ACCEPT;
		    	}
		    	else
		   		{
			  		printk("<hwl>drop\n");
			  		return NF_DROP;
		   		}
		   }
		   else//继续匹配下一条
				ph = ph->next;
		}
		//无匹配 按默认策略
		if (default_action == ACTION_ACCEPT)
			return NF_ACCEPT;
		else
			return NF_DROP;
	}	
	
	return 0;
}


/*
    向规则链表中添加一个规则节点
 */
static int rule_add(rule_node *phead,rule_node *pnew_node)
{
	rule_node *temp = NULL;
	//TRACE_ENTRY;
	temp = (rule_node *)vmalloc(sizeof(rule_node));
	temp->proto = pnew_node->proto;
	temp->srcip = pnew_node->srcip;
	temp->destip = pnew_node->destip;
	temp->srcport = pnew_node->srcport;
	temp->destport = pnew_node->destport;
	temp->action = pnew_node->action;
	rule_node *p = phead;
	while(p->next != NULL)
	{
		p = p->next;			
	}
	p->next = temp;
	temp->next = NULL;
	//TRACE_EXIT;
	return 0;
}

/*
 * 显示规则给用户
 
static int rule_list(rule_node *phead)
{
	//static char buf2[1000];
	//int jj=0;
	//fp_rule=filp_open("./rule.txt",O_RDWR|O_CREAT|O_APPEND,0644);
	rule_node *ph = phead->next;
	int i = 0;
	if(default_action == ACTION_ACCEPT)
		printk(KERN_INFO "Default policy:ACCEPT\n");
	else
		printk(KERN_INFO "Default policy:DROP\n");
    printk( KERN_INFO "<dhh>protocol\tsrcip\t\tsrcport\tdestip\t\tdestport\taction\n");

	while (ph != NULL)
	{

		i++;
		printk("<dhh>%c\t\t",ph->proto);
        printk("%d.%d.%d.%d\t",*((unsigned char *)&ph->srcip),*((unsigned char *)&ph->srcip+1),*((unsigned char *)&ph->srcip+2),*((unsigned char *)&ph->srcip+3));
		printk("%d\t",ph->srcport);
        printk("%d.%d.%d.%d\t",*((unsigned char *)&ph->destip),*((unsigned char *)&ph->destip+1),*((unsigned char *)&ph->destip+2),*((unsigned char *)&ph->destip+3));
		printk("%d\t",ph->destport);

		if (ph->action == ACTION_ACCEPT)
			printk("accept\n");
		else
			printk("drop\n");
		ph=ph->next;
	}

	return MSTATUS_SUCCESS;
}
*/

static int rule_del(rule_node *phead,int index){
	rule_node *pnode = phead;
	rule_node *temp = NULL;
	int i = 0;
	while (pnode->next != NULL)
	{
		i++;
		if (i == index)
		{
			temp = pnode->next;
			pnode->next = temp->next;
			vfree((void *)temp);
			return MSTATUS_SUCCESS;
		}
		pnode = pnode->next;
	}
	return MSTATUS_DEL_ERR;
}

/*
 * 清除规则链
 */
static int rule_clear(rule_node *phead)
{
	rule_node *ph = phead;
	rule_node *temp = NULL;
	printk(KERN_INFO "Clear rule list %s %s\n",  __FILE__,__func__);
	while (ph->next != NULL)
	{
		temp = ph->next;
		ph->next = temp->next;
		vfree((void *)temp);
	}
	return MSTATUS_SUCCESS;
}

/*
 * 开启过滤，即注册回调函数
 */
static int start_filter(void)
{
	//TRACE_ENTRY;
    //fp=filp_open("./log.txt",O_RDWR|O_CREAT|O_APPEND,0644);

	if(hooked == 0)
	{
		hook1.hook     = lwfw_hookfn;         /* Handler function */
		hook1.hooknum  = NF_INET_PRE_ROUTING; /* First hook for IPv4 */
		hook1.pf       = PF_INET;
		hook1.priority = NF_IP_PRI_FIRST;   /* Make our function first */
		nf_register_hook(&hook1);

        hook2.hook     = lwfw_hookfn;         /* Handler function */
		hook2.hooknum  = NF_INET_POST_ROUTING; /* First hook for IPv4 */
		hook2.pf       = PF_INET;
		hook2.priority = NF_IP_PRI_FIRST;   /* Make our function first */
		nf_register_hook(&hook2);

		hooked = 1;
		printk(KERN_INFO "myipfilter start %s function( %s )\n", __FILE__,__func__ );
	}
	//TRACE_EXIT;
	return 0;

}

/*
 * 关闭过滤，即注销回调函数
 */
static int stop_filter(void)
{
	//TRACE_ENTRY;
	//filp_close(fp,NULL);
	if(hooked == 1)
	{
		nf_unregister_hook(&hook1);
		nf_unregister_hook(&hook2);
		hooked = 0;
		printk(KERN_INFO "myipfilter stop %s function( %s )\n", __FILE__,__func__ );
	}
	//TRACE_EXIT;
	return 0;

}

static rule_list(char *buff)
{
	rule_node *ph = phead_rule->next;
	memset(buf,-1,2000);
	int i = 1;
	if(default_action == ACTION_ACCEPT)
		buf[0] = 0;
	else
		buf[0] = 1;
	while (ph != NULL)
	{
		//printk("%c\t\t",ph->proto);
		buf[i] = ph->proto;
        //printk("%d.%d.%d.%d\t",*((unsigned char *)&ph->srcip),*((unsigned char *)&ph->srcip+1),*((unsigned char *)&ph->srcip+2),*((unsigned char *)&ph->srcip+3));
        buf[i+1] = *((unsigned char *)&ph->srcip); 
        buf[i+2] = *((unsigned char *)&ph->srcip+1);
        buf[i+3] = *((unsigned char *)&ph->srcip+2);
        buf[i+4] = *((unsigned char *)&ph->srcip+3);
		//printk("%d\t",ph->srcport);
		buf[i+5] = ph->srcport;
        //printk("%d.%d.%d.%d\t",*((unsigned char *)&ph->destip),*((unsigned char *)&ph->destip+1),*((unsigned char *)&ph->destip+2),*((unsigned char *)&ph->destip+3));
        buf[i+6] = *((unsigned char *)&ph->destip); 
        buf[i+7] = *((unsigned char *)&ph->destip+1);
        buf[i+8] = *((unsigned char *)&ph->destip+2);
        buf[i+9] = *((unsigned char *)&ph->destip+3);
		//printk("%d\t",ph->destport);
		buf[i+10] = ph->destport;
		buf[i+11] = ph->action;
		ph=ph->next;
		i=i+12;
	}
	if(!copy_to_user((char *)buff, buf, sizeof(buf)))
        return sizeof(buf);
  	else
     	return -1;
};


/*
 * ioctl
 */
static int myfilter_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int rc=0;
	void *p = NULL;
	p = (void*)arg;
	switch(cmd)
	{
	case  IOCTL_CMD_START : //开启过滤器 
		{
			rc = start_filter();
		}
		break;
	case IOCTL_CMD_STOP  :  //关闭过滤器
		{
			rc = stop_filter();
		}
		break;
	case IOCTL_CMD_ADDRULE : //添加规则
		{
			rule_node tmp_node;
			int len=0;
			if((len = copy_from_user(&tmp_node, (rule_node *)p, sizeof(rule_node))))
			{
				DPRINTK("copy_from_user():copy arg failed.\n");
				DPRINTK("sizeof(rule_node)=%d\n",sizeof(rule_node));
				DPRINTK("len=%d",len);
				rc = MSTATUS_CP_ERR;
			}
			else
			{
				rc = rule_add(phead_rule, &tmp_node);
			}
		}
		break;
	
	case IOCTL_CMD_DELRULE : //删除规则
		{
			int index=0;
			if( copy_from_user(&index, (int *)p, sizeof(int)))
			{
				DPRINTK("copy_from_user():copy arg failed.\n");
				rc = MSTATUS_CP_ERR;
			}
			else
			{
				rc = rule_del(phead_rule, index);
			}
		}
		break;

	case IOCTL_CMD_CLEAR :	//清除所有规则
		{
			rc = rule_clear(phead_rule);
		}
		break;

	case IOCTL_CMD_LIST :	//显示所有规则
		{
			rc = rule_list((char*)arg);
		}
		break;

	case IOCTL_CMD_SETDEFAULT:
		{
			int action = -1;
			if( copy_from_user(&action, (int *)p, sizeof(int)))
			{
				DPRINTK("copy_from_user():copy arg failed.\n");
				rc = MSTATUS_CP_ERR;
			}
			if (action != -1)
				default_action = action;
		}
		break;
	}
	return rc;
}

/*
 * insmod时调用
 */
static int __init init_myipfilter_module(void)
{


	int rc;
	//int i;
	//TRACE_ENTRY;
	printk(KERN_INFO "Hello, world from %s function( %s )\n", __FILE__,__func__ );
	rc = misc_register(&vms_miscdevice);
	//分配空头结点
	phead_rule=(rule_node *)vmalloc(sizeof(rule_node));
	memset((char *)phead_rule, 0, sizeof(rule_node));
	phead_rule->next=NULL;

   int result,err;
   dev_t devno,devno_m;

   /* Register the control device, /dev/lwfw */
   result = alloc_chrdev_region(&devno, 0, 1, "lwfw");
   major = MAJOR(devno);

   if (result < 0)
     return result;

   devno_m = MKDEV(major, 0);
   printk("major is %d\n",MAJOR(devno_m));
   printk("minor is %d\n",MINOR(devno_m));
   cdev_init(&cdev_m, &myfilter_fops);
   cdev_m.owner = THIS_MODULE;
   cdev_m.ops = &myfilter_fops;
   err = cdev_add(&cdev_m, devno_m, 1);
   if(err != 0 ){
    printk("cdev_add error\n");
   }
   printk("\nipfilter: Control device successfully registered.\n");

	//TRACE_EXIT;
	return rc;  /* Non-zero return code indicates loading failed */
}
/*
 * rmmod时调用
 */
static void __exit cleanup_myipfilter_module(void)
{
	   /* Now unregister control device */
   	cdev_del(&cdev_m);
   	unregister_chrdev_region(MKDEV(major, 0), 1);

	//TRACE_ENTRY;
	printk(KERN_INFO "Goodbye, world from %s function( %s )\n", __FILE__,__func__ );
	//rule_clear(phead_rule);
	vfree((void *)phead_rule);
	stop_filter();
	misc_deregister(&vms_miscdevice);
	//TRACE_EXIT;
}

module_init(init_myipfilter_module);
module_exit(cleanup_myipfilter_module);





