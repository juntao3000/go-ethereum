// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package trie

//
// https://learnblockchain.cn/books/geth/part3/mpt.html#hex-encoding
// https://blog.csdn.net/qq_55179414/article/details/118935827
//

// MPT 是一棵逻辑树，并不一一对应物理树（存储）
// 到达节点的树路径 Path 和节点中记录的 Key 一起构成了节点的完整 Key
// 分支节点的插槽 Index 是树路径的一部分

// Trie keys are dealt with in three distinct encodings:
// 处理trie树中的三种编码格式的相互转换的工作
//
// KEYBYTES encoding contains the actual key and nothing else. This encoding is the
// input to most API functions.
// 这种编码格式就是原生的key字节数组，大部分的Trie的API都是使用这边编码格式
//
// HEX encoding contains one byte for each nibble of the key and an optional trailing
// 'terminator' byte of value 0x10 which indicates whether or not the node at the key
// contains a value. Hex key encoding is used for nodes loaded in memory because it's
// convenient to access.
// 这种编码格式以nibble(半字节)为单位,每一个字节包含了Key的一个半字节，
// 若该 Key 对应的节点存储的是真实的数据项内容（即该节点是叶子节点），则在末位添加终止标志符；
// '终止符' = 0x10 = 16
// 当节点被加载到内存里面的时候使用的是这种key，因为它的方便访问
//
// COMPACT encoding is defined by the Ethereum Yellow Paper (it's called "hex prefix
// encoding" there) and contains the bytes of the key and a flag. The high nibble of the
// first byte contains the flag; the lowest bit encoding the oddness of the length and
// the second-lowest encoding whether the node at the key is a value node. The low nibble
// of the first byte is zero in the case of an even number of nibbles and the first nibble
// in the case of an odd number. All remaining nibbles (now an even number) fit properly
// into the remaining bytes. Compact encoding is used for nodes stored on disk.
// 这种编码格式是黄皮书里面说到的Hex-Prefix Encoding，可以在存储到数据库的时候节约磁盘空间
// 存入到数据库中存在节点 Key 的只有扩展节点和叶子节点，因此 HP 只用于区分扩展节点和叶子节点，不涉及无节点 key 的分支节点
// key 的第一个字节的高4位为前缀标识符,由两部分组成：节点类型和奇偶标识:
// 第一个字节的高4位中的倒数第2位,节点类型标记位,0 表示扩展节点类型，1 表示叶子节点，
// 第一个字节的高4位中的倒数第1位,key长度奇偶标记位,偶为 0，奇为 1。最终可以得到唯一标识的前缀标识：
// 0000 -> 0：扩展节点,偶长度
// 0001 -> 1：扩展节点,奇长度
// 0010 -> 2：叶子节点,偶长度
// 0011 -> 3：叶子节点,奇长度
// 当偶长度时，第一个字节的低四位用0填充，
// 当是奇长度时，则将 key[0] 存放在第一个字节的低四位中，这样 HP 编码结果始终是偶长度。
// 为什么要区分节点 key 长度的奇偶呢？因为半字节 1 和 01 在转换为 bytes 格式时都成为<01>，无法区分两者
func hexToCompact(hex []byte) []byte {
	terminator := byte(0)
	if hasTerm(hex) { // 有终止符,叶子节点
		terminator = 1
		hex = hex[:len(hex)-1] //去掉末尾的终止符
	}
	buf := make([]byte, len(hex)/2+1) // 新长度=原来长度/2 + 一个前缀字节,除以2是把 hex key 的相邻两个'半字节'合并为一个字节
	buf[0] = terminator << 5          // the flag byte // 节点类型,在高4位中的倒数低2位,即位运算左移5位
	if len(hex)&1 == 1 {              // 奇数长度
		buf[0] |= 1 << 4 // odd flag  // 奇偶长度类型,在高4位中的倒数低1位,即位运算左移4位,然后合并 节点类型位 与 奇偶长度类型位
		buf[0] |= hex[0] // first nibble is contained in the first byte // 当奇数长度时，将 key[0] 存放在第一个字节的低四位中
		hex = hex[1:]    // key[0] 已存放在第一个字节的低四位中
	}
	decodeNibbles(hex, buf[1:])
	return buf
}

// hexToCompactInPlace places the compact key in input buffer, returning the length
// needed for the representation
// 就地转换 hex key 为 compact key
func hexToCompactInPlace(hex []byte) int {
	var (
		hexLen    = len(hex) // length of the hex input
		firstByte = byte(0)
	)
	// Check if we have a terminator there
	if hexLen > 0 && hex[hexLen-1] == 16 {
		firstByte = 1 << 5 // 节点类型,在高4位中的倒数低2位,即位运算左移5位
		hexLen--           // last part was the terminator, ignore that //去掉末尾的终止符
	}
	var (
		binLen = hexLen/2 + 1 // 新长度=原来长度/2 + 一个前缀字节,除以2是把 hex key 的相邻两个'半字节'合并为一个字节
		ni     = 0            // index in hex
		bi     = 1            // index in bin (compact) // 第一个字节为前缀
	)
	if hexLen&1 == 1 { // 奇数长度
		firstByte |= 1 << 4 // odd flag // 奇偶长度类型,在高4位中的倒数低1位,即位运算左移4位,然后合并 节点类型位 与 奇偶长度类型位
		firstByte |= hex[0] // first nibble is contained in the first byte // 当奇数长度时，将 key[0] 存放在第一个字节的低四位中
		ni++
	}
	for ; ni < hexLen; bi, ni = bi+1, ni+2 {
		hex[bi] = hex[ni]<<4 | hex[ni+1]
	}
	hex[0] = firstByte
	return binLen
}

func compactToHex(compact []byte) []byte {
	if len(compact) == 0 {
		return compact
	}
	base := keybytesToHex(compact)
	// delete terminator flag
	// 扩展节点,去掉末尾的终止符
	if base[0] < 2 {
		base = base[:len(base)-1]
	}
	// apply odd flag
	// 当偶长度时，第一个字节的低四位用0填充，解码后从第3索引也读取
	// 当是奇长度时，则将 key[0] 存放在第一个字节的低四位中，解码后从第2索引也读取
	chop := 2 - base[0]&1
	return base[chop:]
}

func keybytesToHex(str []byte) []byte {
	// 将原先的一个字节拆成两个半字节,在末尾加上终止符 '16'
	l := len(str)*2 + 1
	var nibbles = make([]byte, l)
	for i, b := range str {
		nibbles[i*2] = b / 16   // 高四位
		nibbles[i*2+1] = b % 16 // 低四位
	}
	nibbles[l-1] = 16
	return nibbles
}

// hexToKeybytes turns hex nibbles into key bytes.
// This can only be used for keys of even length.
func hexToKeybytes(hex []byte) []byte {
	if hasTerm(hex) {
		hex = hex[:len(hex)-1]
	}
	if len(hex)&1 != 0 {
		panic("can't convert hex key of odd length")
	}
	key := make([]byte, len(hex)/2)
	decodeNibbles(hex, key)
	return key
}

func decodeNibbles(nibbles []byte, bytes []byte) {
	for bi, ni := 0, 0; ni < len(nibbles); bi, ni = bi+1, ni+2 {
		bytes[bi] = nibbles[ni]<<4 | nibbles[ni+1]
	}
}

// prefixLen returns the length of the common prefix of a and b.
func prefixLen(a, b []byte) int {
	var i, length = 0, len(a)
	if len(b) < length {
		length = len(b)
	}
	for ; i < length; i++ {
		if a[i] != b[i] {
			break
		}
	}
	return i
}

// hasTerm returns whether a hex key has the terminator flag.
func hasTerm(s []byte) bool {
	return len(s) > 0 && s[len(s)-1] == 16
}
