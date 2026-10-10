package myssh

import (
	"net"
)

// 本文件实现 CIDR 前缀的二进制 Trie（按位分叉），用于 GeoIP 命中判定。
// v4/v6 各一棵树，Contains 沿位下行，命中任一已标记前缀即返回。

type ipTrieNode struct {
	left  *ipTrieNode // 0 分支
	right *ipTrieNode // 1 分支
	isEnd bool        // 标记为一个 CIDR 前缀终点
}

type ipTrie struct {
	v4Root *ipTrieNode
	v6Root *ipTrieNode
}

func newIPTrie() *ipTrie {
	return &ipTrie{
		v4Root: &ipTrieNode{},
		v6Root: &ipTrieNode{},
	}
}

func (t *ipTrie) Insert(ipBytes []byte, prefixLen int) {
	var node *ipTrieNode
	if len(ipBytes) == 4 {
		node = t.v4Root
	} else if len(ipBytes) == 16 {
		node = t.v6Root
	} else {
		return
	}

	// 前缀长度必须有界。geodata 是下载来的数据，不可信：
	//   - prefixLen > len*8 时 ipBytes[i/8] 会越界索引 → panic，而 loadGlobalConfig
	//     在 gomobile 导出层直接被调、外面没有 recover，整个 App 崩；
	//   - prefixLen == 0 时循环体不执行，isEnd 落在**家族根**上，于是
	//     ContainsBytes 对任何地址在 i=0 就命中——整个 IPv4/IPv6 空间都被归入该
	//     标签，流量静默全绕过代理，且无任何报错。
	maxBits := len(ipBytes) * 8
	if prefixLen <= 0 || prefixLen > maxBits {
		return
	}

	for i := 0; i < prefixLen; i++ {
		bit := (ipBytes[i/8] >> (7 - (i % 8))) & 1
		if bit == 0 {
			if node.left == nil {
				node.left = &ipTrieNode{}
			}
			node = node.left
		} else {
			if node.right == nil {
				node.right = &ipTrieNode{}
			}
			node = node.right
		}
	}
	node.isEnd = true
}

func (t *ipTrie) Contains(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		return t.ContainsBytes(ip4, true)
	}
	return t.ContainsBytes(ip.To16(), false)
}

// ContainsBytes 按位匹配、最长前缀语义
func (t *ipTrie) ContainsBytes(ipBytes []byte, isV4 bool) bool {
	var node *ipTrieNode
	if isV4 {
		node = t.v4Root
	} else {
		node = t.v6Root
	}

	for i := 0; i < len(ipBytes)*8; i++ {
		if node == nil {
			return false
		}
		if node.isEnd {
			return true // 已命中某前缀 (例如 10.0.0.0/8)
		}
		bit := (ipBytes[i/8] >> (7 - (i % 8))) & 1
		if bit == 0 {
			node = node.left
		} else {
			node = node.right
		}
	}
	return node != nil && node.isEnd
}
