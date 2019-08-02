#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kernel.h>   
#include <linux/kallsyms.h>
#include <linux/skbuff.h>   

MODULE_DESCRIPTION("Sniffer_Learning");
MODULE_AUTHOR("Kubistika");
MODULE_LICENSE("GPL");

/* disable page protection */
void disable_page_protection(void)
{
	pr_info("DISABLE_PAGE_PROTECTION");
	write_cr0(read_cr0() & (~0x10000));
}

/* enable page protection */
void enable_page_protection(void)
{
	pr_info("ENABLE_PAGE_PROTECTION");
	write_cr0(read_cr0() | 0x10000);
}

/* length of assembly to override */
#define ASSEMBLY_LENGTH 12

/* our function hijacking */
#define ASSEMBLY_JUMP 					\
{	 0x48, 0xb8, 0x00, 0x00, 			\
	 0x00, 0x00, 0x00, 0x00, 			\
	 0x00, 0x00, 0x50, 0xc3				\
}

char jump_assembly[ASSEMBLY_LENGTH] = ASSEMBLY_JUMP;
char trampoline[ASSEMBLY_LENGTH] = ASSEMBLY_JUMP;
unsigned char old_proluge[ASSEMBLY_LENGTH * 2];

unsigned long *jump_pointer = (unsigned long *)(jump_assembly + 2);
unsigned long *trampoline_pointer = (unsigned long *)(trampoline + 2);

static int (*original_netif_receive_skb)(struct sk_buff *skb);
static int (*trampoline_netif_receive_skb)(struct sk_buff *skb);

int hook_netif_receive_skb(struct sk_buff *skb)
{
    /* do some hook stuff */
    pr_info("in hook!");

    disable_page_protection();
    /* call patched prologe */
    (*(void(*)())old_proluge)();
    enable_page_protection();
    return 0;
}

static int kubisti_sniffer_init(void)
{
    disable_page_protection();
    /* fetch address of original function */
    original_netif_receive_skb = (void*) kallsyms_lookup_name("__netif_receive_skb");

    /* override proluge with jump instruction to our hook */
    *jump_pointer = (unsigned long) hook_netif_receive_skb;

    /* save old proluge */
    memcpy(old_proluge, original_netif_receive_skb, ASSEMBLY_LENGTH);

    /* override original function proluge with jump */
    memcpy(original_netif_receive_skb, jump_assembly, ASSEMBLY_LENGTH);

    /* set trampoline pointer to original code, after the direct hook */
    *trampoline_pointer = (unsigned long) original_netif_receive_skb + ASSEMBLY_LENGTH;

    /* append the jump after old prologe */
    memcpy(old_proluge + ASSEMBLY_LENGTH, trampoline, ASSEMBLY_LENGTH);
    enable_page_protection();
    return 0;
}

static void kubisti_sniffer_exit(void)
{
    // TODO: remove hook.
}

module_init(kubisti_sniffer_init);
module_exit(kubisti_sniffer_exit);

