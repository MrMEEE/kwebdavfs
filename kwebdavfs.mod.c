#include <linux/module.h>
#include <linux/export-internal.h>
#include <linux/compiler.h>

MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x8c5c56f8, "inode_init_owner" },
	{ 0x3769df68, "generic_fillattr" },
	{ 0xc8025046, "setattr_prepare" },
	{ 0xa61fd7aa, "__check_object_size" },
	{ 0x35360521, "d_instantiate" },
	{ 0x26906386, "clear_inode" },
	{ 0xeb516d21, "crypto_ecdh_key_len" },
	{ 0x2d51ac71, "simple_strtoll" },
	{ 0xd710adbf, "__kmalloc_noprof" },
	{ 0xf2d6afb7, "folio_unlock" },
	{ 0xab90883d, "new_inode" },
	{ 0x40a621c5, "snprintf" },
	{ 0xda44517b, "simple_strtol" },
	{ 0x39dcd3dc, "unregister_filesystem" },
	{ 0x60c9c0b3, "__init_swait_queue_head" },
	{ 0xc1df51fd, "simple_statfs" },
	{ 0x39b1c268, "d_make_root" },
	{ 0x200918b1, "sock_create" },
	{ 0x45b74520, "d_splice_alias" },
	{ 0x9b3986cc, "current_time" },
	{ 0xfbe7861b, "memcpy" },
	{ 0xcb8b6ec6, "kfree" },
	{ 0x26906386, "iput" },
	{ 0x66526f72, "sg_init_one" },
	{ 0x075cbd92, "crypto_alloc_aead" },
	{ 0xf41396be, "crypto_aead_setauthsize" },
	{ 0x47dc53e4, "crypto_aead_decrypt" },
	{ 0x39dcd3dc, "register_filesystem" },
	{ 0x1b821b52, "kernel_recvmsg" },
	{ 0xd272d446, "__fentry__" },
	{ 0x519ffa96, "crypto_destroy_tfm" },
	{ 0x5a844b26, "__x86_indirect_thunk_rax" },
	{ 0x26906386, "unlock_new_inode" },
	{ 0xe8213e80, "_printk" },
	{ 0x86a99672, "crypto_alloc_kpp" },
	{ 0x329fc928, "in4_pton" },
	{ 0xbd03ed67, "__ref_stack_chk_guard" },
	{ 0xd272d446, "__stack_chk_fail" },
	{ 0x59fac341, "make_kuid" },
	{ 0xcd03a5ed, "truncate_inode_pages_final" },
	{ 0xd710adbf, "__kmalloc_large_noprof" },
	{ 0x9479a1e8, "strnlen" },
	{ 0x296b9459, "strrchr" },
	{ 0x90a48d82, "__ubsan_handle_out_of_bounds" },
	{ 0xbd03ed67, "page_offset_base" },
	{ 0xcd5bd969, "hkdf_extract" },
	{ 0x26906386, "inode_init_once" },
	{ 0x44decd6f, "hugetlb_optimize_vmemmap_key" },
	{ 0xedc1f40d, "dns_query" },
	{ 0xfe867a0d, "crypto_aead_setkey" },
	{ 0x4c3f741c, "crypto_req_done" },
	{ 0x06e36f3a, "init_net" },
	{ 0x1e469f10, "hkdf_expand" },
	{ 0x902463d0, "generic_file_read_iter" },
	{ 0xe9beea87, "crypto_shash_setkey" },
	{ 0x08a22404, "match_int" },
	{ 0x366ddfcc, "memchr" },
	{ 0x47dc53e4, "crypto_aead_encrypt" },
	{ 0x17545440, "strstr" },
	{ 0xbd03ed67, "random_kmalloc_seed" },
	{ 0xe9ddf13a, "setattr_copy" },
	{ 0x3a67d45b, "set_nlink" },
	{ 0xf46d5bf3, "mutex_lock" },
	{ 0xe981281f, "kmem_cache_free" },
	{ 0x2435d559, "strncmp" },
	{ 0x6848eb64, "const_current_task" },
	{ 0x0762d1bc, "crypto_shash_digest" },
	{ 0xf8faa012, "kfree_sensitive" },
	{ 0x5a844b26, "__x86_indirect_thunk_r13" },
	{ 0x680628e7, "ktime_get_real_ts64" },
	{ 0x402db74e, "memcmp" },
	{ 0x173ec8da, "sscanf" },
	{ 0xc1e6c71e, "__mutex_init" },
	{ 0xe54e0a6b, "__fortify_panic" },
	{ 0x4e72d1e0, "crypto_ecdh_encode_key" },
	{ 0x0e80a22b, "kernel_connect" },
	{ 0x0e9cab28, "memset" },
	{ 0x5a844b26, "__x86_indirect_thunk_r10" },
	{ 0x65026e43, "wait_for_completion" },
	{ 0xd272d446, "__x86_return_thunk" },
	{ 0xdd0e0f53, "kmem_cache_alloc_noprof" },
	{ 0x6c535bbc, "make_kgid" },
	{ 0x7fd710be, "__kmem_cache_create_args" },
	{ 0xec203997, "kasprintf" },
	{ 0x888b8f57, "strcmp" },
	{ 0x62bb6f8b, "truncate_setsize" },
	{ 0x058c185a, "jiffies" },
	{ 0xce4af33b, "kstrdup" },
	{ 0xbd03ed67, "vmemmap_base" },
	{ 0x9e2ccf67, "mount_nodev" },
	{ 0xa5c7582d, "strsep" },
	{ 0xf46d5bf3, "mutex_unlock" },
	{ 0xb689121e, "strnstr" },
	{ 0x26906386, "inc_nlink" },
	{ 0x7de510a1, "match_token" },
	{ 0x957c6137, "__kmalloc_cache_noprof" },
	{ 0x546c19d9, "validate_usercopy_range" },
	{ 0xfa42a949, "hex_to_bin" },
	{ 0x27444811, "_copy_from_iter" },
	{ 0xb6b5894f, "sock_release" },
	{ 0x923584d8, "match_strdup" },
	{ 0xcc20dd8d, "generic_file_open" },
	{ 0x224a53e7, "get_random_bytes" },
	{ 0x3af91c18, "kill_anon_super" },
	{ 0xfb860512, "d_parent_ino" },
	{ 0xaf818948, "iget5_locked" },
	{ 0xd272d446, "rcu_barrier" },
	{ 0xe4de56b4, "__ubsan_handle_load_invalid_value" },
	{ 0x43a349ca, "strlen" },
	{ 0x296b9459, "strchr" },
	{ 0x8c4c0b59, "crypto_alloc_shash" },
	{ 0xce03c8c3, "__mark_inode_dirty" },
	{ 0x0232ea06, "generic_file_llseek" },
	{ 0xcc8d9ef4, "kernel_sendmsg" },
	{ 0x26906386, "drop_nlink" },
	{ 0x7851be11, "__SCT__might_resched" },
	{ 0x78339609, "kmalloc_caches" },
	{ 0x9c70c945, "inode_set_ctime_to_ts" },
	{ 0xfbe26b10, "krealloc_noprof" },
	{ 0x6da5974d, "kmem_cache_destroy" },
	{ 0x86c49e96, "nop_mnt_idmap" },
	{ 0x984622ae, "module_layout" },
};

static const u32 ____version_ext_crcs[]
__used __section("__version_ext_crcs") = {
	0x8c5c56f8,
	0x3769df68,
	0xc8025046,
	0xa61fd7aa,
	0x35360521,
	0x26906386,
	0xeb516d21,
	0x2d51ac71,
	0xd710adbf,
	0xf2d6afb7,
	0xab90883d,
	0x40a621c5,
	0xda44517b,
	0x39dcd3dc,
	0x60c9c0b3,
	0xc1df51fd,
	0x39b1c268,
	0x200918b1,
	0x45b74520,
	0x9b3986cc,
	0xfbe7861b,
	0xcb8b6ec6,
	0x26906386,
	0x66526f72,
	0x075cbd92,
	0xf41396be,
	0x47dc53e4,
	0x39dcd3dc,
	0x1b821b52,
	0xd272d446,
	0x519ffa96,
	0x5a844b26,
	0x26906386,
	0xe8213e80,
	0x86a99672,
	0x329fc928,
	0xbd03ed67,
	0xd272d446,
	0x59fac341,
	0xcd03a5ed,
	0xd710adbf,
	0x9479a1e8,
	0x296b9459,
	0x90a48d82,
	0xbd03ed67,
	0xcd5bd969,
	0x26906386,
	0x44decd6f,
	0xedc1f40d,
	0xfe867a0d,
	0x4c3f741c,
	0x06e36f3a,
	0x1e469f10,
	0x902463d0,
	0xe9beea87,
	0x08a22404,
	0x366ddfcc,
	0x47dc53e4,
	0x17545440,
	0xbd03ed67,
	0xe9ddf13a,
	0x3a67d45b,
	0xf46d5bf3,
	0xe981281f,
	0x2435d559,
	0x6848eb64,
	0x0762d1bc,
	0xf8faa012,
	0x5a844b26,
	0x680628e7,
	0x402db74e,
	0x173ec8da,
	0xc1e6c71e,
	0xe54e0a6b,
	0x4e72d1e0,
	0x0e80a22b,
	0x0e9cab28,
	0x5a844b26,
	0x65026e43,
	0xd272d446,
	0xdd0e0f53,
	0x6c535bbc,
	0x7fd710be,
	0xec203997,
	0x888b8f57,
	0x62bb6f8b,
	0x058c185a,
	0xce4af33b,
	0xbd03ed67,
	0x9e2ccf67,
	0xa5c7582d,
	0xf46d5bf3,
	0xb689121e,
	0x26906386,
	0x7de510a1,
	0x957c6137,
	0x546c19d9,
	0xfa42a949,
	0x27444811,
	0xb6b5894f,
	0x923584d8,
	0xcc20dd8d,
	0x224a53e7,
	0x3af91c18,
	0xfb860512,
	0xaf818948,
	0xd272d446,
	0xe4de56b4,
	0x43a349ca,
	0x296b9459,
	0x8c4c0b59,
	0xce03c8c3,
	0x0232ea06,
	0xcc8d9ef4,
	0x26906386,
	0x7851be11,
	0x78339609,
	0x9c70c945,
	0xfbe26b10,
	0x6da5974d,
	0x86c49e96,
	0x984622ae,
};
static const char ____version_ext_names[]
__used __section("__version_ext_names") =
	"inode_init_owner\0"
	"generic_fillattr\0"
	"setattr_prepare\0"
	"__check_object_size\0"
	"d_instantiate\0"
	"clear_inode\0"
	"crypto_ecdh_key_len\0"
	"simple_strtoll\0"
	"__kmalloc_noprof\0"
	"folio_unlock\0"
	"new_inode\0"
	"snprintf\0"
	"simple_strtol\0"
	"unregister_filesystem\0"
	"__init_swait_queue_head\0"
	"simple_statfs\0"
	"d_make_root\0"
	"sock_create\0"
	"d_splice_alias\0"
	"current_time\0"
	"memcpy\0"
	"kfree\0"
	"iput\0"
	"sg_init_one\0"
	"crypto_alloc_aead\0"
	"crypto_aead_setauthsize\0"
	"crypto_aead_decrypt\0"
	"register_filesystem\0"
	"kernel_recvmsg\0"
	"__fentry__\0"
	"crypto_destroy_tfm\0"
	"__x86_indirect_thunk_rax\0"
	"unlock_new_inode\0"
	"_printk\0"
	"crypto_alloc_kpp\0"
	"in4_pton\0"
	"__ref_stack_chk_guard\0"
	"__stack_chk_fail\0"
	"make_kuid\0"
	"truncate_inode_pages_final\0"
	"__kmalloc_large_noprof\0"
	"strnlen\0"
	"strrchr\0"
	"__ubsan_handle_out_of_bounds\0"
	"page_offset_base\0"
	"hkdf_extract\0"
	"inode_init_once\0"
	"hugetlb_optimize_vmemmap_key\0"
	"dns_query\0"
	"crypto_aead_setkey\0"
	"crypto_req_done\0"
	"init_net\0"
	"hkdf_expand\0"
	"generic_file_read_iter\0"
	"crypto_shash_setkey\0"
	"match_int\0"
	"memchr\0"
	"crypto_aead_encrypt\0"
	"strstr\0"
	"random_kmalloc_seed\0"
	"setattr_copy\0"
	"set_nlink\0"
	"mutex_lock\0"
	"kmem_cache_free\0"
	"strncmp\0"
	"const_current_task\0"
	"crypto_shash_digest\0"
	"kfree_sensitive\0"
	"__x86_indirect_thunk_r13\0"
	"ktime_get_real_ts64\0"
	"memcmp\0"
	"sscanf\0"
	"__mutex_init\0"
	"__fortify_panic\0"
	"crypto_ecdh_encode_key\0"
	"kernel_connect\0"
	"memset\0"
	"__x86_indirect_thunk_r10\0"
	"wait_for_completion\0"
	"__x86_return_thunk\0"
	"kmem_cache_alloc_noprof\0"
	"make_kgid\0"
	"__kmem_cache_create_args\0"
	"kasprintf\0"
	"strcmp\0"
	"truncate_setsize\0"
	"jiffies\0"
	"kstrdup\0"
	"vmemmap_base\0"
	"mount_nodev\0"
	"strsep\0"
	"mutex_unlock\0"
	"strnstr\0"
	"inc_nlink\0"
	"match_token\0"
	"__kmalloc_cache_noprof\0"
	"validate_usercopy_range\0"
	"hex_to_bin\0"
	"_copy_from_iter\0"
	"sock_release\0"
	"match_strdup\0"
	"generic_file_open\0"
	"get_random_bytes\0"
	"kill_anon_super\0"
	"d_parent_ino\0"
	"iget5_locked\0"
	"rcu_barrier\0"
	"__ubsan_handle_load_invalid_value\0"
	"strlen\0"
	"strchr\0"
	"crypto_alloc_shash\0"
	"__mark_inode_dirty\0"
	"generic_file_llseek\0"
	"kernel_sendmsg\0"
	"drop_nlink\0"
	"__SCT__might_resched\0"
	"kmalloc_caches\0"
	"inode_set_ctime_to_ts\0"
	"krealloc_noprof\0"
	"kmem_cache_destroy\0"
	"nop_mnt_idmap\0"
	"module_layout\0"
;

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "76ECAB8DB8BEA9DB9BD4DC7");
