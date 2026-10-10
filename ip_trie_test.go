package myssh

import (
	"net"
	"testing"
)

// 回归：Insert 的前缀长度必须有界。
// geodata 是下载来的数据，不可信——这两条越界路径各自对应一个严重事故：
// 越界索引 panic（gomobile 导出层无 recover → 整个 App 崩），以及前缀 0 命中
// 家族根（整个地址空间被归入该标签 → 流量静默全绕过代理）。

func TestIPTrieInsertRejectsOutOfRangePrefix(t *testing.T) {
	ip := net.ParseIP("10.0.0.1").To4()
	for _, prefix := range []int{-8, -1, 0, 33, 64, 128, 256} {
		t.Run("", func(t *testing.T) {
			trie := newIPTrie()
			// 修复前 prefix=33 在 ipBytes[i/8] 处 panic，prefix=0 会把 v4Root 标成 isEnd。
			trie.Insert(ip, prefix)
			if trie.Contains(ip) {
				t.Fatalf("prefix=%d must not insert, but Contains(10.0.0.1) == true", prefix)
			}
			// 家族根被误标时，任何同族地址都会命中。
			if trie.Contains(net.ParseIP("203.0.113.9").To4()) {
				t.Fatalf("prefix=%d marked the v4 family root", prefix)
			}
		})
	}
}

func TestIPTrieInsertRejectsOutOfRangePrefixV6(t *testing.T) {
	ip := net.ParseIP("2001:db8::1").To16()
	for _, prefix := range []int{0, 129, 512} {
		trie := newIPTrie()
		trie.Insert(ip, prefix)
		if trie.Contains(net.ParseIP("2001:db8::1")) || trie.Contains(net.ParseIP("fe80::1")) {
			t.Fatalf("prefix=%d must not insert", prefix)
		}
	}
}

// 越界插入必须是「静默忽略」而不是污染已有内容。
func TestIPTrieInsertOutOfRangeKeepsExistingEntries(t *testing.T) {
	trie := newIPTrie()
	trie.Insert(net.ParseIP("10.0.0.0").To4(), 8)
	trie.Insert(net.ParseIP("10.0.0.0").To4(), 0)  // 若误标家族根，会让下面两条断言都失败
	trie.Insert(net.ParseIP("10.0.0.0").To4(), 32) // 若误走越界索引，这里 panic

	if !trie.Contains(net.ParseIP("10.1.2.3")) {
		t.Fatal("10.0.0.0/8 no longer matches 10.1.2.3")
	}
	if trie.Contains(net.ParseIP("11.0.0.1")) {
		t.Fatal("10.0.0.0/8 must not match 11.0.0.1")
	}
	if trie.Contains(net.ParseIP("::1")) {
		t.Fatal("a v4 prefix must not mark the v6 tree")
	}
}

func TestIPTrieLongestPrefixSemantics(t *testing.T) {
	trie := newIPTrie()
	trie.Insert(net.ParseIP("192.0.2.0").To4(), 24)

	if !trie.Contains(net.ParseIP("192.0.2.200")) {
		t.Fatal("192.0.2.0/24 must match 192.0.2.200")
	}
	if trie.Contains(net.ParseIP("192.0.3.1")) {
		t.Fatal("192.0.2.0/24 must not match 192.0.3.1")
	}
}

// 非法长度（既不是 4 也不是 16 字节）一直就应被忽略。
func TestIPTrieInsertRejectsBadLength(t *testing.T) {
	trie := newIPTrie()
	trie.Insert([]byte{1, 2, 3}, 24)
	if trie.Contains(net.ParseIP("1.2.3.0")) || trie.Contains(net.ParseIP("1.2.3.255")) {
		t.Fatal("a 3-byte address must be ignored")
	}
}
