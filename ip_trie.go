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
