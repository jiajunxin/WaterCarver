package crypto

import (
	"fmt"
)

var Identity_p3 ExtendedGroupElement

type MultiexpData struct {
	Scalar Key
	Point ExtendedGroupElement
}

func AppendMultiexpData(data *[]MultiexpData, point *Key, scalar *Key) {
	var _point ExtendedGroupElement
	_point.FromBytes(point)
	*data = append(*data, MultiexpData{Point:_point, Scalar:*scalar})
}

type Straus_cached_data struct {
	Multiples [][]CachedGroupElement
}

const STRAUS_C = 4

func lessThan(k0 *Key, k1 *Key) bool {
	for n := 31; n >= 0; n-- {
		if k0[n] < k1[n] {
			return true
		}
		if k0[n] > k1[n] {
			return false
		}
	}
	return false
}

func pow2(n int) (res *Key) {
	res = new(Key)
	*res = Zero
	res[n >> 3] |= 1 << uint(n & 7)
	return
}

func test(k Key, n int) int {
	if n >= 256 {
		return 0
	}
	return int(k[n >> 3] & (1 << uint(n & 7)))
}

func add(p3 *ExtendedGroupElement, other *CachedGroupElement) {
	var p1 CompletedGroupElement
	geAdd(&p1, p3, other)
	p1.ToExtended(p3)
}

func add3_3(p3 *ExtendedGroupElement, other *ExtendedGroupElement) {
	var cached CachedGroupElement
	other.ToCached(&cached)
	add(p3, &cached)
}

func straus(data *[]MultiexpData, cache *Straus_cached_data, STEP int) (result Key, err error) {
	if cache != nil && (len(cache.Multiples) < 1 || len(cache.Multiples[1]) < len(*data)) {
		err = fmt.Errorf("Cache is too small ")
		return
	}
	if STEP <= 0 {
		STEP = 192
	}
	local_cache := cache
	if local_cache == nil {
		local_cache, err = straus_init_cache(data, 0)
		if err != nil {
			return
		}
	}

	var cached CachedGroupElement
	var p1 CompletedGroupElement

	digits := make([]uint8, 64 * len(*data))
	for j := 0; j < len(*data); j++ {
		bytes := (*data)[j].Scalar[:]
		for i := 0; i < 64; i += 2 {
			digits[j * 64 + i] = bytes[0] & 0xf
			digits[j * 64 + i + 1] = bytes[0] >> 4
			bytes = bytes[1:]
		}
	}
	maxscalar := Zero
	for i := 0; i < len(*data); i++ {
		if lessThan(&maxscalar, &(*data)[i].Scalar) {
			maxscalar = (*data)[i].Scalar
		}
	}
	start_i := 0
	for start_i < 256 && !(lessThan(&maxscalar, pow2(start_i))) {
		start_i += STRAUS_C
	}

	res_p3 := Identity_p3

	for start_offset := 0; start_offset < len(*data); start_offset += STEP {
		num_points := len(*data) - start_offset
		if num_points > STEP {
			num_points = STEP
		}

		band_p3 := Identity_p3
		i := start_i
		skip := false
		if !(i < STRAUS_C) {
			skip = true
		}
		for !(i < STRAUS_C) {
			if !skip {
				var p2 ProjectiveGroupElement
				band_p3.ToProjective(&p2)
				for j:= 0; j < STRAUS_C; j++ {
					p2.Double(&p1)
					if j == STRAUS_C - 1 {
						p1.ToExtended(&band_p3)
					} else {
						p1.ToProjective(&p2)
					}
				}
			}
			i -= STRAUS_C
			for j := start_offset; j < start_offset + num_points; j++ {
				digit := digits[j * 64 + i / 4]

				if digit != 0 {
					geAdd(&p1, &band_p3, &local_cache.Multiples[digit][j])
					p1.ToExtended(&band_p3)
				}
			}
			skip = false
		}

		band_p3.ToCached(&cached)
		geAdd(&p1, &res_p3, &cached)
		p1.ToExtended(&res_p3)
	}

	res_p3.ToBytes(&result)
	return
}

func straus_init_cache(data *[]MultiexpData, N int) (cache *Straus_cached_data, err error) {
	if N == 0 {
		N = len(*data)
	}
	if N > len(*data) {
		err = fmt.Errorf("Bad cache base data ")
		return
	}
	var p1 CompletedGroupElement
	var p3 ExtendedGroupElement
	cache = new(Straus_cached_data)
	cache.Multiples = make([][]CachedGroupElement, 1 << STRAUS_C)
	offset := 0
	cache.Multiples[1] = make([]CachedGroupElement, N)
	for i := offset; i < N; i++{
		(*data)[i].Point.ToCached(&cache.Multiples[1][i])
	}
	for i := 2; i < (1 << STRAUS_C); i++ {
		cache.Multiples[i] = make([]CachedGroupElement, N)
	}
	for j := offset; j < N; j++ {
		for i := 2; i < (1 << STRAUS_C); i++ {
			geAdd(&p1, &(*data)[j].Point, &cache.Multiples[i-1][j])
			p1.ToExtended(&p3)
			p3.ToCached(&cache.Multiples[i][j])
		}
	}
	return
}

func pippenger(data *[]MultiexpData, cache *Pippenger_cached_data, cache_size int, c int) (_result Key, err error) {
	if cache != nil && cache_size == 0 {
		cache_size = len(cache.cached)
	}
	if cache != nil && cache_size > len(cache.cached) {
		err = fmt.Errorf("Cache is too small ")
		return
	}
	if c == 0 {
		c = get_pippenger_c(len(*data))
	}
	if c > 9 {
		err = fmt.Errorf("c is too large ")
		return
	}

	result := Identity_p3
	result_init := false
	buckets := make([]ExtendedGroupElement, 1 << uint(c))
	var buckets_init []bool
	local_cache := cache
	if local_cache == nil {
		local_cache, err = pippenger_init_cache(data, 0, 0)
		if err != nil {
			return
		}
		//cache_size = len(*data)
	}
	var local_cache2 *Pippenger_cached_data
	if len(*data) > cache_size {
		local_cache2, err = pippenger_init_cache(data, cache_size, 0)
		if err != nil {
			return
		}
	}

	maxscalar := Zero
	for i := 0; i < len(*data); i++ {
		if lessThan(&maxscalar, &(*data)[i].Scalar) {
			maxscalar = (*data)[i].Scalar
		}
	}
	groups := 0
	for groups < 256 && !(lessThan(&maxscalar, pow2(groups))) {
		groups++
	}
	groups = (groups + c - 1) / c

	for k := groups - 1; k >= 0; k-- {
		if result_init {
			var p2 ProjectiveGroupElement
			result.ToProjective(&p2)
			for i := 0; i < c; i++ {
				var p1 CompletedGroupElement
				p2.Double(&p1)
				if i == c - 1 {
					p1.ToExtended(&result)
				} else {
					p1.ToProjective(&p2)
				}
			}
		}
		buckets_init = make([]bool, 1 << uint(c))

		for i := 0; i < len(*data); i++ {
			bucket := 0
			for j := 0; j < c; j++ {
				if test((*data)[i].Scalar, k * c + j) != 0 {
					bucket |= 1 << uint(j)
				}
			}
			if bucket == 0 {
				continue
			}
			if bucket >= (1 << uint(c)) {
				err = fmt.Errorf("bucket overflow")
				return
			}
			if buckets_init[bucket] {
				if i < cache_size {
					add(&buckets[bucket], &local_cache.cached[i])
				} else {
					add(&buckets[bucket], &local_cache2.cached[i - cache_size])
				}
			} else {
				buckets[bucket] = (*data)[i].Point
				buckets_init[bucket] = true
			}
		}

		var pail ExtendedGroupElement
		pail_init := false
		for i := (1 << uint(c)) - 1; i > 0; i-- {
			if buckets_init[i] {
				if pail_init {
					add3_3(&pail, &buckets[i])
				} else {
					pail = buckets[i]
					pail_init = true
				}
			}
			if pail_init {
				if result_init {
					add3_3(&result, &pail)
				} else {
					result = pail
					result_init = true
				}
			}
			/*
			var tmp Key
			pail.ToBytes(&tmp)
			fmt.Printf("k: %d i:%d pail:%s ", k, i, tmp)
			result.ToBytes(&tmp)
			fmt.Printf("result:%s\n", tmp)
			*/
		}
	}

	result.ToBytes(&_result)
	return
}

func get_pippenger_c(N int) int {
	if N <= 13 {
		return 2
	}
	if N <= 29 {
		return 3
	}
	if N <= 83 {
		return 4
	}
	if N <= 185 {
		return 5
	}
	if N <= 465 {
		return 6
	}
	if N <= 1180 {
		return 7
	}
	if N <= 2295 {
		return 8
	}
	return 9
}

type Pippenger_cached_data struct {
	cached []CachedGroupElement
}

func pippenger_init_cache(data *[]MultiexpData, start_offset int, N int) (cache *Pippenger_cached_data, err error)  {
	if start_offset > len(*data) {
		err = fmt.Errorf("Bad cache base data ")
		return
	}
	if N == 0 {
		N = len(*data) - start_offset
	}
	if N > len(*data) - start_offset {
		err = fmt.Errorf("Bad cache base data ")
		return
	}

	cache = new(Pippenger_cached_data)

	cache.cached = make([]CachedGroupElement, N)
	for i := 0; i < N; i++ {
		(*data)[i + start_offset].Point.ToCached(&cache.cached[i])
	}
	return
}

func Multiexp(data *[]MultiexpData, HiGi_size int) (Key, error) {
	if HiGi_size > 0 {
		if HiGi_size <= 232 && len(*data) == HiGi_size {
			return straus(data, straus_HiGi_cache, 0)
		} else {
			return pippenger(data, pippenger_HiGi_cache, HiGi_size, get_pippenger_c(len(*data)))
		}
	} else {
		if len(*data) <= 95 {
			return straus(data, nil, 0)
		} else {
			return pippenger(data, nil, 0, get_pippenger_c(len(*data)))
		}
	}
}

const STRAUS_SIZE_LIMIT = 232
const PIPPENGER_SIZE_LIMIT = 0
var straus_HiGi_cache *Straus_cached_data
var pippenger_HiGi_cache *Pippenger_cached_data

func InitCache(data []MultiexpData) {
	Identity_p3.FromBytes(&Identity)
	pstraus_HiGi_cache, err := straus_init_cache(&data, STRAUS_SIZE_LIMIT)
	if err != nil {
		panic("fail to init cache for multiexp ")
	}
	ppippenger_HiGi_cache, err := pippenger_init_cache(&data, 0, PIPPENGER_SIZE_LIMIT)
	if err != nil {
		panic("fail to init cache for multiexp ")
	}
	straus_HiGi_cache = pstraus_HiGi_cache
	pippenger_HiGi_cache = ppippenger_HiGi_cache
}