//
// 5-wire Poseidon hash function parameters
//

#define ROUND_COUNT_5W  53
#define SPONGE_WIDTH_5W 5
#define SPONGE_RATE_5W  4
#define SBOX_ALPHA_5W   7

// Round constants
static const Field _round_keys_5w[ROUND_COUNT_5W][SPONGE_WIDTH_5W] =
{
  {
    {0x6342181358ae2f17, 0x5a321a1614499301, 0x4359bc382232456a, 0x3c06cd69a97c028b},
    {0xc8f709e31405ba8d, 0x2ad4d6aa3c7651a4, 0x64ceac42dd7ccf06, 0x35c6bf27e315e7b9},
    {0x42218b11632afaf, 0x90b0a10532f0546, 0x9e04edfc8863e7f9, 0x1ff6086dc7ed5384},
    {0x16d30e86f07fe92b, 0x49034fc6f7a0437c, 0x7e969951637e0a28, 0x290172d88a15ab18},
    {0xd254d8abb8cde612, 0xd4661c22ac9199eb, 0x512959a2410883d0, 0x35b38913f7bb3552}
  },
  {
    {0x49f9638de015c972, 0xad7264c15c3300ef, 0xa62f4865d8c45b04, 0x315e43c0ae02c353},
    {0xb3801cb83df2182f, 0xcaaccf3669280a81, 0xd23d1db585bf366e, 0x116befc5fb4b732a},
    {0x208bcd0d2edd006c, 0x10eb450d1445d24e, 0x430c3ea6421ac01c, 0x2faf9819445679d3},
    {0x7d2dedb966b0ebb4, 0x4209eee542441a34, 0xf0d333d24b06af71, 0x10dedf831bfe44d8},
    {0x382b013bde3a59ae, 0xebafdd87c283d4af, 0x32d9c8ef1bce04a8, 0x37556fb5c9dfe161}
  },
  {
    {0xe7016d6ae4ed55a4, 0xbadf50c278ef084f, 0x5f2fc45b67f08884, 0x718c8e8163346fb},
    {0x2d21d77bdfad5760, 0x6ed140b4216a3a63, 0x43b402fb536c00d2, 0xb47d43fb0ea216d},
    {0x36a2aed80574b2f1, 0x43955b0622809eb3, 0x6feacba71072e845, 0x28df76e003ac1ce6},
    {0x95e3a1a7336bd728, 0xd87d937c7f109e25, 0x8ce854afc1645048, 0x2fd788ebb6f37b5e},
    {0x4e4171605858df04, 0x6f56c8c5f323deed, 0x6a570e86d39294ba, 0x6a33164c054814e}
  },
  {
    {0xe182b857a075e511, 0x1246b8af401e6e, 0x498681baac02e546, 0x317e99888d6935e3},
    {0xbbb9ff9616a4c70, 0xbd5c5a42104dcf4, 0x92895e7865a8d476, 0x3c40b0adcfe6deb8},
    {0xfc63b58d228c1ad9, 0xb912e4ec588e1a52, 0x601be7d93b9e73fe, 0x1d52635b6bf4a796},
    {0x8defc77d5096467a, 0xfb8b83bb3cee16b9, 0x1498e0216590fc1d, 0x337571eb0ad8f47a},
    {0x8fed932080f3d458, 0x8a1ca06c98c3849f, 0x1644f9415395314f, 0x2919282dc8950b51}
  },
  {
    {0x749d4e7efe5fad9b, 0x33b58b4510a5f0a1, 0xce62030d41fdca38, 0x239d5d59f87e0ddf},
    {0x55d59bdcc39fb71b, 0x7c183b304cad27d1, 0xb84182c63c47f121, 0x2469351d6d7b0ac4},
    {0xbe942f1ad599f550, 0xfa1e12f8c552df88, 0x1ce36aa79f22cf45, 0x18e7e49a56a18f41},
    {0x5a85fc171d1c0130, 0xee3b8aebc4fb144c, 0xb7910bda1c5a2946, 0x2ef6a9412227b683},
    {0xe3f397f0634ba64, 0xb24c5da645b804a8, 0x8efdcb393a1c51d1, 0x388a37934aa31a42}
  },
  {
    {0xf0aeba711a86d351, 0x917e0a9875d8182e, 0x255ebbbe4e9633da, 0x3edb9c2a8feb51c7},
    {0xf7085a35274435d5, 0x4e859571631715f8, 0xd465913c64aecaac, 0x3df65e7104e3d373},
    {0x95964ef5b04dba5a, 0x86296dcb59e4f8b5, 0x340fae9fdeb8e75e, 0x3c095e04bcd91636},
    {0x6ca87eaf42d54b9d, 0x5efd6b2fd3843e9a, 0x1a9120a05cc3b07c, 0xbb0503c4b83daca},
    {0xfdd237f0786fa203, 0x76e67649a894dff6, 0xcea3a7485eb3522, 0x371ed39b30e34b8}
  },
  {
    {0xb9ea58fb107cee4e, 0xea9f1a7f2d6d936f, 0x60883d0bd19662e8, 0x137e698d12aceebf},
    {0x37d5024d477cbc47, 0xbd489bbac329f617, 0x37201ef9b7544c1f, 0x1019235cf42868cb},
    {0xa676a36a225fd2d0, 0x16c1d622bd02030a, 0x71b81aab0eacb647, 0x36af1193dcd5753f},
    {0xe00395d80fc7fa84, 0x2122fd483a170d2e, 0x6786ca04c13fbe30, 0x159d681f1d489146},
    {0xacbab2cc73b4508f, 0x47443d2762112d66, 0x26c9a77344312882, 0xa68b32d6c0b1024}
  },
  {
    {0xe5943e9ec5816b5f, 0x78f97275cb9e7f63, 0x28d993db0402e6f5, 0x35023474a298a50a},
    {0xd5f6f7304d58bd86, 0xbeed688b64192acc, 0xd7211bea14f1a406, 0x24f92d631c9c4bc},
    {0x6952a1fd17d693e3, 0xc04dd964f234b8cf, 0x7caf0fe8884ef070, 0x1c1fdcd698bf94b5},
    {0xca8b6804ac41ba2d, 0x81794823bc0576ff, 0xd4a19f41722a0f09, 0x2846565f83dc9972},
    {0x51ea8b6d4a20f06e, 0xcfc9a709b77cbe9d, 0x30ff8818851924e9, 0x211d3ce41b7ee763}
  },
  {
    {0xff21fe3230917894, 0xab2870fddeb86f88, 0x62e4a41add2270a6, 0x15884194ae363d14},
    {0x4a6fb13b70e67a19, 0xc5247d0dba887080, 0x31b4c6c5e685c605, 0x2e9f9208fcc2515a},
    {0x1c90f4fb1e0414b4, 0x8ff65aee4323cf80, 0xa13dda064773ad4d, 0x810a513ddf12c38},
    {0xe053ad98a6ec9bef, 0x39b9faf0e080b472, 0x818c7ad0f950eae0, 0xf1cd4227514673},
    {0xd196b25dc683b945, 0xd724c2ad624ad4a9, 0xa02ff7daa5b740a1, 0x15d55dbe3c7b4e13}
  },
  {
    {0xb315a1ea41fe829c, 0x18713cd306622126, 0x6118592ab4ec0503, 0x3ed3f347d4db5134},
    {0x5975228afeaccf0c, 0xfe4e4239b60b0efc, 0xc9cca90df89e496b, 0x230f526cd9442560},
    {0x5a49f311ef676e8a, 0xad7cb07e3ed9efad, 0x2a417082abc3cf1a, 0x21601ac12eba703e},
    {0xdf338b83df06f68c, 0x63cd7cb53f8cdce4, 0x1f0fdaf0eecf7ab6, 0xcb74130d7ea6889},
    {0xd99c453addc57eae, 0x2e5ca7b4ccd548e9, 0x1d61848bbc4141ef, 0x1502dc917545edad}
  },
  {
    {0x31688174ae3a3088, 0xc2f2735e215a8858, 0xe021199a3e4ad81c, 0x3c3a13210a719854},
    {0x5cd766b0b1aa7928, 0x9469f3c1ab1f06d1, 0x23c181781a8a1af8, 0x669f23736966be7},
    {0x5e43af558f0a0b, 0x7568a76e8644aa47, 0xa49bfc0b2c3a0969, 0xdaabd0e2866cfd8},
    {0x3f57582785bde7cc, 0x95a273aed529176e, 0xef25328aff37a9e8, 0x116b8853ab55ee5a},
    {0xeda91d71ffd7b2a0, 0x6efe645946126c4c, 0xe9f09dd2a7027804, 0x387a2c92b4e648d5}
  },
  {
    {0x64ab4aa2e9f0aff2, 0xe966eeaf6883d60c, 0xb94697e6a3a0a4df, 0x38f0fc799ed7a14a},
    {0x1511dd33c4afdbf3, 0xe36ee2b5ffe811cc, 0x505a5de39ec98985, 0x3df8294a06678e64},
    {0xc710119f6242f55d, 0x2466c6cb6d325477, 0xb1774657e651de5, 0x310d190e78ee5dfd},
    {0xb1e6071ea081861b, 0xe92b3ce474295159, 0x77456109d94dc351, 0x1d893fd638fd7a1b},
    {0xc782a16511338c59, 0xd18c9bc3c41203d7, 0x847badef6c2b829f, 0x126c269e06a4a430}
  },
  {
    {0xa0e7271d058e1b65, 0xc29f191eed5dc914, 0x89207dbde1650706, 0x1bd2a2d62a9947b2},
    {0x6ae20ca1c2d65d68, 0x80f9d7daed9c8c8c, 0xad5cf3b156b2f1de, 0x509f8b72998a87c},
    {0xb03a6b97357d97f0, 0x593eee3fbeacfe95, 0x9fee173d856a5b7c, 0x133fc88ee7b23b27},
    {0x4b9a0736e24a0f26, 0x405d5a665f66fbc4, 0x4d4d5268d0b8b9d9, 0x3238606d9b26856a},
    {0xd073bfc69cab34f0, 0xb4133b646eb1841b, 0x10a149c352b6f7df, 0x20cf915f29d33c57}
  },
  {
    {0x307d2b8cb0fd415, 0xc8319598907073a4, 0x6b773db66a05a6a2, 0x33e6c0d1d806c5ce},
    {0xc08315afa7ec4292, 0xdf1042b5d5054c91, 0xa610476590769545, 0x354676a843acb066},
    {0xa1c7c9de915601be, 0x69cadc4f1bbf31a7, 0x47661b8d743f21e, 0x2939e4566b8e1260},
    {0xf8166d26b5875ae8, 0x391c8625906a68c9, 0x97a671ae3e7920b6, 0xb62d4ddc6a61f73},
    {0x5b13bd8369bec282, 0xe2ea0c100e5347a6, 0x2d9c57262923cb1, 0x1e31165d6dc07d45}
  },
  {
    {0x3df3f3bfd54018f2, 0xca762a746d00043e, 0x25022728a3503107, 0xd5efa7f874457bc},
    {0x613e721107b4b48d, 0xf10823eec3d12df3, 0xeb54dfa62698b875, 0x243340259e551904},
    {0x1ce630ba8530b2a4, 0x6f5eddfa4f7ddda2, 0xdffb5a531052c7b4, 0x3c6b192f75dff4c1},
    {0x8d8f971036624659, 0xebd0ccfe39e0803e, 0xebdcb61a65d66931, 0x21868796aae7a40b},
    {0x22e12b186fa512c7, 0x4968f02a800e1ecc, 0x4725f2ec01f4b71e, 0x28e74c6a4f22fcb9}
  },
  {
    {0xeffca0f81d56aa11, 0xcb0ae88503b5be82, 0x69b43848fe8e74c1, 0xf0b271c54f3b2a3},
    {0x23db18e63a2414b1, 0x7eba0c1ea4e2d784, 0x72108a3064e1a124, 0x138c36a9897505ac},
    {0xb93afa2c44d2b18f, 0x616aef5e3ec452fe, 0xcb15eebb579916f7, 0xed9d9c3d23aaa60},
    {0x19c722ddc6d11a6c, 0x933aa7e601881608, 0x3d680c98391faed1, 0x2809e56840f1eca3},
    {0x682adeb5d9a53026, 0xcdb02ab94f3e9259, 0xed7adc874c00a2d4, 0x1764188e52d76c52}
  },
  {
    {0x2cb2173bfd2a8b7d, 0x742418360f62a8f4, 0xffa5daf7a2f06510, 0x2622bec30f05eda4},
    {0x956300c0a931ef90, 0x3e8dcd122d9b3016, 0xd77959f2fba021a4, 0x51f68f4d9b5836a},
    {0xcca7550f4e2663fb, 0x3a7115aac8cd273a, 0xfa9108f48b6ec0f7, 0x2eb9ac59d63b2756},
    {0x25c658fd552f8699, 0x24c4b27a4de55c10, 0xf2a39825d38a8469, 0x261dc2c828f9be1c},
    {0xf33c05063dced35a, 0xb0dada5d213d36ea, 0xe1a0c81f1f6ca22f, 0x3b5ea3d73588bcf5}
  },
  {
    {0x5938e55ad487efbc, 0x65ff0bdaa2002589, 0x24f12d149cfb0ad8, 0x2d7f7be151666e78},
    {0x832fab7224860b2d, 0xc9f4cdbadd955fa2, 0x4aedceb5506c2655, 0x1c44fa130dd1ecc7},
    {0x7d034b1f6a58ddaf, 0xf897b22ef62bf04f, 0xd973ac696faf14aa, 0x31548d27d817dbcc},
    {0xf89844128d9c6ae6, 0xfc4cfe0229c7aab1, 0xac2b0c7d97647680, 0x1e1d5254aa0782f9},
    {0xe8c1dd74ba3631f0, 0xd81c8d077b5a6f56, 0xf3294e721e883318, 0x380d3a1eab70459b}
  },
  {
    {0xaba511448d72ecf, 0xbf82f1fdf1687a8e, 0x6313bb88e45ffa56, 0x2ae425e1e1234cff},
    {0xf4a6807d301a531f, 0x96429863d70e0604, 0x15bdd9eae828ddc7, 0x31f0f80173fe31d7},
    {0x3a6d20e8dea8c483, 0x2adca6c88e7509ef, 0x48b1d6d05be6c961, 0x35053945aa6e5402},
    {0xdc5f96bd86658107, 0x5aee32dc2a32affb, 0xe200cec62dc0d495, 0x1055b57944bf554b},
    {0xe1ca0c53b24b06d, 0x528de276ea0c8c5e, 0x1c7ffa0b483f3002, 0x1c72f58595847427}
  },
  {
    {0x26a28a08b5b246ea, 0xba3b8d9f4f4b0f41, 0x99c9ed2c1fcf4a3e, 0x58070c1e7b659c5},
    {0x7aa8e9a2d203b7f4, 0x9acb8ddb590fc9a0, 0xd7cf3e5554e162c, 0x17769ee1912d75e1},
    {0x6c6901252870a99d, 0x9a4108b035e55928, 0x297dab35f2c77cae, 0x31f2978ace0f7e2d},
    {0xfcf1119abff1e989, 0xe8502332327be648, 0xa8918572496177c5, 0x1710468c2227c8d6},
    {0xdd2bf9131735dd76, 0xe43ec3b817349505, 0x61ec884ee479524b, 0x377c72d607beacc5}
  },
  {
    {0xa9bef84e0b68b0e8, 0x2c4c8f2ab7b0c9fc, 0xee234cad52493f69, 0x1c5bd50dc4a1fced},
    {0x57f989e88a97334c, 0xf99d4d667c1b859a, 0x64164c1e8e48da1b, 0x36b841653e8612c5},
    {0xb55c8effbf87f8d8, 0xe15c71abf8372eb, 0xc606d853488806ff, 0x2c6be0beffd5a9b3},
    {0x97235a2b7f573c80, 0x8f5053ff091130d7, 0x201611ece80cd2e6, 0x22498e90ad20fd7b},
    {0xb25923ea87f4f825, 0x1faf60a8b1d87720, 0x1c480f9378722c18, 0x187ba4d5f603542d}
  },
  {
    {0x2553e37a713a8650, 0x4af5a87c8bb53cde, 0x9470f8df7dc4e62a, 0x1147db739156a158},
    {0x7a58fe90b257b6b7, 0x8ee9df6553d968a9, 0x85057b2342c19359, 0x3ca66ad9e8533b29},
    {0xebe091f37f855e8b, 0x78312923a64e1e08, 0xf968ab79c1cb96b, 0x84c6a2f87e5877d},
    {0xd3393bcf45ec7f72, 0xeebaad3d085cc500, 0x8dfb7b13fe964753, 0x29e0048c6a967c5},
    {0x6ee6f52f14c5c52b, 0x51eda970b620a200, 0xe1239122e1ee6ed3, 0x20241311a411c6dd}
  },
  {
    {0x3a632070a61738d0, 0x58360c4de1248c90, 0x2007e0611a3ddc78, 0x318e43c7104b5d29},
    {0xe11a8859f0b07f43, 0x22423a78bf5d6ce7, 0xfe8417dfe2f81f05, 0x2a9cf2284ea93e6},
    {0x3c682a7371dae56a, 0xb537b6fc7564fea3, 0x4c8c6573f55fa435, 0x152489488b5a1639},
    {0x3cf49703bdb0de0, 0xf828bf910f380e10, 0x8fb14d900fd140d1, 0x3f6cf44c3e3ff6db},
    {0x7b70aeec460c3296, 0x2afdb7b9dd091761, 0xe5b3b021d8f70e09, 0x1f75fbbd77a4b405}
  },
  {
    {0xb824cf8de5beaed8, 0x70a7fe173b87433b, 0x1a8efeec667f72e4, 0x39565d2fad0c609a},
    {0x5cd0203a1d4f951, 0xdb78389b84917080, 0x6c4c97504ab70cd5, 0x29cc98e95cf64495},
    {0x6bc75c72ecd52b50, 0x33afc1a9068b1413, 0x33daf830e0a55f27, 0x71875230561158e},
    {0xb19ed2b87a280098, 0x1e9ed62c5d6a622e, 0xf1c47cd609238e2b, 0x88c1888884476d},
    {0x69ea31042e6e347f, 0x9bb2a44f8642afdb, 0xeccc2d81df513162, 0x3af58f661fb1f19c}
  },
  {
    {0x46713a78770b8c85, 0xb3ccf0a4b425690e, 0xc65beb7710375cf8, 0x1c83ac2e75d29e4e},
    {0x8df4d89a09fbc390, 0x4d57e4b593fc2239, 0x94b4e16defc746d7, 0x1e00fdaba6801cc9},
    {0x62d3e199fefcf465, 0xddfca365e5282190, 0xadd48dd560275162, 0x250a1b6745f9c2a6},
    {0x935e7ff4c5ad3690, 0x931629e4dcf656, 0xad870e5416ca92d0, 0x2d2002e4c1a7fb42},
    {0x3020c37bbe98a69f, 0x3bbbef2df0bb0743, 0x735468317fea682d, 0x3bb75622e8ae0e5}
  },
  {
    {0x6d101c64f48442cb, 0x9c4d0d7cabbe37d0, 0x6e457716d0cc5c54, 0x131685a66db0333d},
    {0x48bcf6f7121dc6fa, 0x44ea62ad25ddb6aa, 0x8636e258625c8e02, 0x171b08836f73a4a4},
    {0x7b5d53163078c6db, 0x79f022d48797b027, 0x8a6611711def9ec3, 0x281eb0327e36241a},
    {0xe807c130c139b23f, 0x8bd55fb76af83b50, 0x2917722317575e1b, 0x8f90e5cd2c3173a},
    {0x4759babec3357d26, 0x265b8a66badcbb36, 0x44df217c22db1fd1, 0x23c7ef2b68b42cf3}
  },
  {
    {0xb6a7c51b7ecb6bc, 0x4d1ae5944bfbeed8, 0x864b9db1caabff7e, 0x39f90ff79f187276},
    {0xd1969a2901b910c2, 0x67af6508acaf97a2, 0x8380c23a59ae6c60, 0x271d877b5644c4a3},
    {0xe17e8fd5a391261a, 0xab17b0e6a4632c50, 0x1c3e97e07f259c9c, 0x2d07bd641a6586e2},
    {0x138aae9b3cd42fb3, 0x81f64f590fb78cb4, 0x885724f615f7f233, 0xa63fee53381d1b6},
    {0x2ec005773e160199, 0x475ef3383e134dd2, 0xce774f49e51de44a, 0x36ef885cefb664f8}
  },
  {
    {0x37420d26e384e4a8, 0x1742df50ce970b26, 0x99f3ea60e2297d13, 0x291cc0cacac121bb},
    {0x59992f7b95d59d06, 0xbfbbbce9ffae7ef8, 0x230d4b9bb86868f8, 0x135612cee5c3cbf5},
    {0x6ab6b33ab48fd8b4, 0x2c46df90b0bdae8c, 0x31e33e7cf970f45a, 0x36c4a50b91a1475a},
    {0xaad1c48efff98a5d, 0x7a478e439cc52346, 0xb77125717607cc5d, 0x24c45ff83f2e80a8},
    {0x5103153d6fdd5dfd, 0x45b61844136521c6, 0x41c397561d8772fd, 0x1ed1ee06b89dbf2e}
  },
  {
    {0x6c5059eebd2c5991, 0x3d6cf236df839e48, 0xd92711e12b52886b, 0x29829fb71567bb3a},
    {0x771a7702e2a54d3a, 0x29b8e99e7644939b, 0x3d453254475ea815, 0x2e5f8163d03b6cb5},
    {0x263df2c33bcdbc46, 0xfed7cba7787b1a36, 0xc315fa3c16682da4, 0x2ab983af9d9b6f25},
    {0x8a0353e693c8e2c, 0xbe92370d0d219261, 0x723aa4237242dd57, 0x25361783d1e56fc3},
    {0x7e7de67d78a9ff19, 0x83c2d2fd23156a32, 0xe65e5d243aa459b6, 0x35813f92ed31f777}
  },
  {
    {0x4819c016f5a5c698, 0x4f72e64273a5868e, 0x61751f954f65b95d, 0x379db14ab6232b32},
    {0x5d8d95a7f9270b96, 0x61541332ec3b7a2b, 0xbf5b05056d41baab, 0xcaf69513fccef00},
    {0x966ebe56652901fd, 0x3d01e1815a5244ad, 0xd62a7487593ee708, 0x5f1ef41b294e025},
    {0xda81a0814d58ed14, 0xe5824bb0a3739516, 0xe559c39f79e50e7f, 0x3cf706e11c52afd4},
    {0xb07502481fd9ac00, 0xbe85d565f578f9e9, 0x25e2168d537c5428, 0x1f8caff53a89afab}
  },
  {
    {0x67ef0684d24ef4d6, 0xe479b8723faeeb8a, 0xed152c7174bce1c6, 0x2c3879d3206619b},
    {0xc0d0b18f192aac4d, 0x8ff92db980036473, 0x39a88f384fb77d28, 0x9fe5e9d746e308b},
    {0xf10d5629175358d0, 0xa258ea27ec17d224, 0x3730ea6667ba6289, 0x1f8bfc64890f7e59},
    {0x5f8c12d96d37065d, 0x4d7ee138862aa83, 0x4a18488a63ce6118, 0x1930781a4f270e4},
    {0xbd4453cefd9ebc0c, 0x14827cfda7ed7ee8, 0x3dd6c45400957559, 0x33c9719ccdaab5b6}
  },
  {
    {0xed0c855c5de359df, 0x6871e8f1798b7bf5, 0x3803b19eb2c1f511, 0x1b88826bc36516df},
    {0xecec6a0bd180a9c0, 0x954e9adfdd68e064, 0x323c890828d78811, 0x2c89829ba7ac7fe7},
    {0x623862b5c28aed0f, 0x544fea8657153f5f, 0x41139508c925a0b2, 0x10d5e06354bae812},
    {0xeae3b52c47a3ad31, 0xa40c52de4949ba9d, 0x239515052b2d0bb6, 0xc68f2ca20bfa5a4},
    {0x86da286806879c23, 0x2bc62129dce2d327, 0x8f8f1b3f3a607809, 0x257de258bba457f3}
  },
  {
    {0xe55015708a8bf114, 0x8f7b7799abb7e89f, 0xcb8fa2a6bf9b602d, 0x1dd3b45e4f2bd1e9},
    {0xa48bd0f7b831b6af, 0xbe6ed2ae7e9b5ea6, 0xecdd091614986315, 0x1bcc64e2d4434539},
    {0xee95991ac731a5d7, 0xb643176046b51d45, 0xf396998dc25f72a3, 0x1474b46564931dc3},
    {0xe8973ad2df550e5e, 0x8561e0de83378bad, 0x90495ddc20bf8d64, 0x2c8ee5b7e87d23ea},
    {0xf15e8598d3360040, 0xd9237d9f5bd4da94, 0x2f32ec74a0b7cb8f, 0x2bfa790791857d69}
  },
  {
    {0x51ed3818b8a671e0, 0x93f8de29901b0101, 0xdd6948f429d84a64, 0x339864f118ba5599},
    {0x8070718964c6881, 0x664a56735cd1d096, 0x966ebb68ce0c59be, 0xdb44ab4420ed185},
    {0x390fdea200fe8c8d, 0xb9ddf1781fc7dcfc, 0x6ccc8d97ea91a52b, 0xaf86429842ad1ea},
    {0x6fbc15b9f8ee61d5, 0x485407282205ba19, 0x9f2b3a9eb0762424, 0x1167e61f6e4bd42e},
    {0x9b2e606d2a12a53f, 0xfe4ee2337eadcc76, 0x97152598ff76e36b, 0x275e80f05a7648b6}
  },
  {
    {0xc3cc461cc12d86e3, 0x48b15302057c1d0e, 0xef7a34bbb6748beb, 0x286c7795696d139},
    {0x337d4ce46c81b278, 0x2e5feb77948c70d3, 0xd82b4f43ac0ebab0, 0x23a5e817dfdebe91},
    {0x2ce1459a01867e26, 0x224b53d8806aa3a5, 0x1bba8ab295cb47f5, 0x6cbbeb19cc3e900},
    {0x1774396945cf1d1b, 0x325ec3d335425b6b, 0xdaf58659cd291e5, 0x3f8cfcb73cb1aff7},
    {0x31812080ad76a765, 0x76b57d46db21d506, 0xa9f0b894c076a2b, 0x6328153e24ddb21}
  },
  {
    {0x635e53a6c9b16d33, 0x39a4746bf0a3364b, 0x61555f31318c6ae0, 0x3b775cd07e4fa0ba},
    {0x2cc47754e893144e, 0x76f56441be34ac0c, 0x580502c5981f6c05, 0x3f1912d87eb51724},
    {0x4ead108af1a4e97c, 0x14ed7a0fc16f0e1a, 0x88a0cf37b2ee10aa, 0x13aa67b47ce7c7fd},
    {0xf54922d903cdce93, 0x825eb6a0321c91fa, 0x6d71f23e5b2a77ae, 0x31d82d03cd7ef1f8},
    {0xf6c8ba6acea0c3a8, 0x3dcdacfe5ace7aa0, 0xbbbff1c714c8bbcb, 0x26b4c61ca5f05c8e}
  },
  {
    {0xc2bddbeee6db7663, 0x5de993fdf4bee2bc, 0xc5598a002460bb6a, 0x195ed57ac7350182},
    {0xa3c22c35da970f5e, 0xca1c98fb8ebbea38, 0x1fac0f5c50dfc365, 0x1aef8ca61af69bd9},
    {0x26e8837fb91809f1, 0xf9688f1eec8f7e7e, 0x610d6fea8d7fdb89, 0x3d0a1bd4d427b4ac},
    {0x4805ec51b5a8b95, 0x35841575c48b553f, 0xefc86563cec776dc, 0x2840e92680329f35},
    {0x88aadc874b15e054, 0xf4c407659f438e86, 0xc78f11dc3ac39010, 0xe83c809dce62ea5}
  },
  {
    {0xa0d5b4ce25ad95e3, 0x4eb48fba265577ca, 0xec34d547e740b067, 0xf87455a1a87a825},
    {0x7171a3dbff618247, 0x8f77af4f143160e8, 0x639543558218623e, 0x1ad8547be9074db4},
    {0xa0dbdf918c38f312, 0x62d083dc471500fb, 0x5358448cc9aad1d1, 0x5825571f70873cd},
    {0xb9c01a42ad74f7f3, 0x96425e46aa40f166, 0xbc305b6f8c2ca3c1, 0x38885a0e462a0d16},
    {0x1f3b4561c10caa2, 0xe7f7e2edd641ea35, 0xd946c46002ec9b24, 0x22dc4744611dfaf}
  },
  {
    {0x89d2596131b9d801, 0x6d61479c7e6f6d9, 0xf5aad5649f5a1c79, 0x225393c033553d15},
    {0x5b0fdd7cbea91565, 0x95e46f19a0dffebc, 0x91d50f19a3a46071, 0x2c03ec2d9ea3aaaf},
    {0xdecba3c94506fd1b, 0xa07f4c4397072961, 0xc072d04541ab3761, 0x250beb5d4be1732e},
    {0x9ce4550f36a82208, 0xad906f79c2991285, 0x82adb87da0fe9206, 0x34aff80145dc173b},
    {0xb84407732055b44d, 0xf9c85a0309677606, 0x1816b1a6361d2c99, 0x302b805797745fa1}
  },
  {
    {0xbbfbaa3655132a2f, 0x85de63edc71b8169, 0x231b387734b227a0, 0x791e6d7e390ab58},
    {0x846a348eee728261, 0x91e35881244dcaed, 0x8755e3179f39f84, 0x11c757c8adbbcee2},
    {0xdc5b85ce4ff2e16, 0xe6680a9d77d56b79, 0x2e1d8a190b81a71b, 0x110440e7f341ccbf},
    {0xc5714f4e64e4f5b5, 0x9073123174ba32aa, 0xd1aafcb808fb13a9, 0x2b0bf27c449467b4},
    {0x674d2c9c2a9f6c33, 0xd64a81fc8872e544, 0x54da3af1c7ea91f3, 0x22bb7d2c8479681d}
  },
  {
    {0x5ea26e9a08f957a5, 0x531b4a8427d261c2, 0x92a9d9e3c38cfcf0, 0x2006044428827241},
    {0xf0834849c1fecda7, 0xfab565ee5f9319d, 0x3a3b976275b87643, 0x2bc18d1039d22ce7},
    {0x7ad9bd18d3ef9d11, 0x136c2bdc157de581, 0xf1999edaa1f99ec6, 0x3bdb875af3652fea},
    {0xb06ff1fa4faa6be7, 0x7b65a2d09d62e6fe, 0xd52851aa16d4a33d, 0x3b7e6a651e5f1100},
    {0x70b297d3bd617bde, 0x42dfd73b30a28150, 0xbcbc0b930ad9480c, 0x14452569cf1b7495}
  },
  {
    {0xb997f89dc4f23510, 0x86aeec894d2eb890, 0x40b5eb4203777c22, 0x3f6900dd45610c9},
    {0xbed1fbbc558ae3b9, 0x7b9919fc76fb8f31, 0xa8155c8d8f223d05, 0x7be199f23efc89b},
    {0x124bd2f29dfdfc99, 0xa3cd06dc334c28dc, 0x8321717bb314584c, 0x7a90593068a94cf},
    {0x6d262cbbd1c3c7a3, 0xfa55dbcbb37ab4e4, 0xdfb0541244749109, 0x1b42310efbbc8ae1},
    {0x159b02d7b19c8807, 0xa3155c41a3100f0b, 0x649691f59c73a27d, 0xb1c6cf5eaa1a3da}
  },
  {
    {0x56a321c5d5620a4e, 0xd704e017be94ce48, 0xbb7e58300ff6e106, 0x231353460278eda6},
    {0x7f24d9a9e896902, 0x379dfae44f3dd605, 0xa756baa38400f59f, 0x1ca15e781769cff3},
    {0x3b1d025a762cebf4, 0x9be99c300caf395, 0x1ec3a4ee83fc2b9c, 0x1db9c130790aa77c},
    {0x92f350103a625f89, 0x7f7abde4baa7fe7c, 0xdb4ce7149975b21a, 0x37619aef93207815},
    {0x2df14ae96e32f360, 0x8154a50068c1d6d7, 0x3696523ff84dccbd, 0x3d71103fe9b7d2cc}
  },
  {
    {0xdc8f123847c2f6f0, 0x772b9f5f133bb07a, 0xf48472df2de5637d, 0xb30587972382d91},
    {0xd32076031e6caf, 0x7a70c0a191315b1, 0xc72d68ebbd493f22, 0x26a6b863263ca385},
    {0xd1ad7a8f3f52bc58, 0x7fd97d9102a5e717, 0xdc4dea9fba06a94f, 0x24292fae82eb3182},
    {0x9c8f6b9aed0c14a, 0x7ce6499a8da0ffc5, 0x4c575abbd55a091, 0x2ffffd706225c6b5},
    {0x51ff57474553fd13, 0xbcd2c2f63e851309, 0xad42d629fbc07620, 0x37cb8a314456dcb3}
  },
  {
    {0x9e725f4a1ea322f0, 0x51275d226f5fc65d, 0xcc96b5ceb521cae0, 0x31697ac9e08fd09a},
    {0xfbbfc3ed25936e24, 0x885d8e71956e9fbf, 0xb8e0d819be1b2b0c, 0x2a27ec07450706e5},
    {0xb86f23d85d56ff2, 0x25630952048f156b, 0x96949d2297030e85, 0x28ed6be9457a4c1d},
    {0x85cefc2d5a4254e4, 0x93335e124a410406, 0xe2caa252d7d83ee, 0x206bb8d1b294acc2},
    {0xaf3c9df6a0ed5396, 0xce5b0093a6e41bfb, 0xdae7d2b6669cdd65, 0x91670d7e0c906e}
  },
  {
    {0x848e19c09bf3ab82, 0xd37733a864fbf5b1, 0x5834568186cadc57, 0x3d8894b3840c836b},
    {0xcb24e184ea8d715, 0xdde18b32791992e1, 0xc754f597613dec6e, 0x124ddceb631af8ac},
    {0x200fede77fe9ccaa, 0x4120a35be4499eb2, 0x6bcb74340da3069e, 0x18d40006660a4d9},
    {0x8ccd91c1dc2b219e, 0x1dc15dbbeee5b7cc, 0x30e961143289ebc0, 0x33aebd15476f6d},
    {0xd4c03228e1165ff1, 0xe755127566374ca5, 0x5eb5e5f7835f51b9, 0x11d1f3f590664116}
  },
  {
    {0x1c2a43421f2b006a, 0x6258ea61fff6649b, 0x5a847a0bdf1ff16b, 0x2038498881736f80},
    {0xe603ee6ce8b0bbc6, 0x620a0a604d315efa, 0x40378c0521e6518d, 0x2d4d8c63bccec23},
    {0xa77ca49f7f8b90ff, 0xcb7652bf1a0cf5ea, 0x3d911a1c6e5c74c3, 0x1a8c15f40c9e99d6},
    {0x293a2d7589738448, 0xea4c1d5f407e77d5, 0xee7f4d7f7d8d69f0, 0x6d9a037bd4006b5},
    {0x7e0382dbce83b459, 0x8210fa8a33a15c2c, 0x4da8c81848a7e20f, 0x35c902f371d587a5}
  },
  {
    {0x3d331566c2c6c483, 0xc66d7c43cf6c6899, 0x7c1c36147e850129, 0x18396a316e009c03},
    {0x16d27bc62b29f952, 0x65a7c24e59dc8b05, 0x5c0acd2a0f886241, 0x15e74885451d7b84},
    {0xe3a5b84fbaedfd4b, 0xfd3304cb4b735b85, 0x8d8df8b6031ccd91, 0x603d2627ed921bc},
    {0x194cd2aa6240d213, 0xa3d4d947c6027d50, 0x7355e133684d2417, 0x3a4ad2ca80689906},
    {0x754062c7dfe10fb, 0x15be7881422ab514, 0xbd3cb5e4447b5b04, 0x267919778e6db957}
  },
  {
    {0x9e687a0099aafbe4, 0x8716f500deb883a4, 0xc7c44b3a4227e0f9, 0x36dfbee5ac583fec},
    {0xb9c5848f3b063542, 0xbd7beb77de16d02e, 0x6ed1369422f1597f, 0x35cd85390d4f063e},
    {0x50a256d280092fdc, 0xd2c2b4dbbb258e39, 0x9c6679aa1c4480db, 0x383efabe992c0d62},
    {0xb8fadb8a950482a8, 0x6279eecfb927c631, 0xf8b75e3cffc23fbd, 0x239433b63ac65264},
    {0xaf95feec451ffd03, 0x7ad4f5520a280f0a, 0xfb6d86aa8efee6c6, 0x5ad99e8a107bd86}
  },
  {
    {0xd47e6d75a1e72978, 0xec21efdeed48fc4c, 0x3f95628431615152, 0x321e3149a1bd5bda},
    {0x366a1936303c4a03, 0xda1980c0a597dd0f, 0x2fddc599df0832d5, 0x10090314b014c0af},
    {0x9af98513b8fa3e32, 0x76a99773a39804d6, 0x49ed6650bc0128d4, 0x34fce51deddd27d8},
    {0x29ccc4a9b0c2b010, 0x8a8f514b705229fe, 0xc1e6d12b311256f4, 0x3291611fbb2fab1e},
    {0xcb4ebbb08bdb9c9d, 0x744ebe7f914218fb, 0xe77c5babcec8a686, 0x2d42a41428a90175}
  },
  {
    {0x8ec3d97ab5616a9e, 0xe8014e7c1141e6ff, 0xa8daca3054309538, 0x1c08ef18d73c76fc},
    {0xcf92950eb4f3789b, 0xaaa450f22a280bf6, 0xc9e4a80c9f2cd996, 0x27f4ac96508752f6},
    {0x7bbd2ed16a76edc6, 0xd8e2186c7de847db, 0x2aa88a2b65118dd0, 0x1c55b5f615dc28ea},
    {0x7ccf57f28acc118a, 0xf5d3c6eb14e65154, 0xdc079fcf442a0f54, 0x11993cb931932e5a},
    {0xf76b4a8906e70667, 0xda7f02e1bf4e36df, 0xaab6b7f1de20dd0f, 0x19fc46ff2ddb173c}
  },
  {
    {0x3a3d2dc8cc132eee, 0xf357bef4e1d3a63c, 0xd48a3a0eb2bc1415, 0x2bc75acfaee9db1},
    {0x5fbb66b806674243, 0xf73af3e558a86209, 0x5d30fbb40ede547c, 0x501e03ee293fd1d},
    {0xe90568a8237171ac, 0x650fc27c4da7f2e3, 0x546a3b7012993072, 0x87e3d6d0e54850d},
    {0xd5dfc1afce8127cb, 0xc6874ecb5b959056, 0x17d19ee832e735c7, 0xbf09138a8fe4ccb},
    {0x489c20a8f79b4f58, 0xaa9a7c84d23aedd3, 0xb66eddf614963ee3, 0x2dbf9ab7c2343a43}
  },
  {
    {0x3dfd42b46f1e6946, 0x58f29edf399435ba, 0x2521d4287bc79d64, 0x1781fbca8872f93c},
    {0x6d6aed7cb045289f, 0x44132433ac541a78, 0x660c1badd4c7e0de, 0x30330b4022cfe5fa},
    {0x31b90687198ee938, 0xf9b1217c09a47868, 0x1df6bdd931eb2b30, 0x151f40cfa7ce6982},
    {0x9049df43bd2b446c, 0xc117a3d9f6656367, 0xfd356803d03495d8, 0x200e3c9d4c1b8eb8},
    {0x90d2cc13778a0928, 0x9b7d207f836f7d68, 0xac2d328e8bc0cdb3, 0xc70770d5c26e2ae}
  }
};

// MDS matrix
static const Field _mds_matrix_5w[SPONGE_WIDTH_5W][SPONGE_WIDTH_5W] =
{
  {
    {0x32f4f94379d14f6, 0x666eef381fb1d4b0, 0xd760525c85a9299a, 0x70288de13f861f},
    {0x2ab57684465d1ca, 0xf12514d37806396c, 0x825085389a26a582, 0x308efdddaf47d944},
    {0x1b2098a19e203e93, 0x914dcdea2a56e245, 0xc64ed9aa2aef8379, 0xb176f95c389478e},
    {0xf895153087f5dca3, 0xa53543f74c7e98f, 0xf5a0b430a14b8c2d, 0x6ae54007a872b0},
    {0xfd0c32f86be981dc, 0xf60dbc5c1bd0b583, 0xd4f3f8f9a2a4537c, 0x1d71b70d52f42936}
  },
  {
    {0x8f85e752c76f7c9c, 0x8297f4f031b02763, 0x30e4ea62df5067b7, 0x2821d0423006dcae},
    {0x5cece392cc5d403f, 0x123da1ba8becd2de, 0x193510960c81a54f, 0x1be17f43c42fe5c0},
    {0x65fc36e3c120e5dd, 0x51a4797b81835701, 0x3123b2b88ae51832, 0x19f174900d86138a},
    {0x6d0db66a74936d4b, 0x1b8aa34d8d4554ad, 0x8605b5c1a219423d, 0x3055d8d876253885},
    {0x9b8b22118b0179db, 0xe14da53ccd481770, 0x109e7ae5ae61278d, 0x13cd85bd55c2f52e}
  },
  {
    {0xd03df46130dd77b4, 0xe694d8c7d8fd4ef4, 0xf71d2a65470713aa, 0x255c475344778d2c},
    {0x78597119a27f97bb, 0x1b1fb7c15ccb3746, 0xb86d8ab32d6a6edf, 0xb1e00f75148f670},
    {0x875597b15bf7ed8d, 0x73fa4e676bb9cc5f, 0x96babdc32ae359e, 0x31e6d9f5ccaa763e},
    {0xf27e0f92236fd303, 0x6e607a16f84adab, 0x4cc8addf91894557, 0x1fb0a70aa0f1061c},
    {0xfd2a420b19b31725, 0xddc5361119d53b6e, 0x3d58af3f6737f156, 0x1350a7bb521c58a6}
  },
  {
    {0xf88f2f863cb9d6fb, 0x5078f8e89e8f9ff9, 0xc5583fcea6176010, 0x25e363acdb694459},
    {0x2ece0c297d2f49a2, 0x9ccc88a13c91abae, 0x4138c965288c3d87, 0x437768eb72dfb4f},
    {0x9fab22e085f93fe5, 0x63ca08a361b7fb0d, 0x7e9790bf5bd5837a, 0x6080ada873c8216},
    {0x32d3b34d8c43a402, 0x2c7e5748fb940669, 0xc0a36e42a28c6f80, 0x24ac3e6b181bb185},
    {0x470f7d02d1dae46, 0x8cf3cde540035d00, 0xe3c0216f8d5d807b, 0x3e3e8312ef71fa39}
  },
  {
    {0x6682f4469913559f, 0x3b053e58dc4560d6, 0xf84c58444b5bdccf, 0xc3230d834c17967},
    {0xbff2a45de17e9da7, 0x6309bfdc8e152f51, 0xb9ae2f9af1f30a1b, 0x27a8797c59f97b06},
    {0xd787c4dd405d1b3f, 0x7da8effab83f1842, 0xb3f8303ad313dac2, 0x3a1a7a3002e72833},
    {0x327b7f748a0695fa, 0x7dde58a92f496b95, 0x8a02b6088016449c, 0x1cef42b151422c3d},
    {0xb22ffb451127fa1a, 0x3c17ca7183462744, 0x4de2e19b12854d65, 0x20938ee131fc7ef0}
  },
};

// Initial sponge state testnet
static const Field _testnet_iv_5w[SPONGE_WIDTH_5W] =
{
  {0x63d01a5eb2171352, 0xa156f498468c138a, 0x6863ea2849c3a1a2, 0x9d3a988f1f410b1},
  {0x7102a042f3032c7a, 0xec792d3bae28c836, 0x56ca8c6f048bc984, 0x1219b5fcf34e0a1f},
  {0x2ac12e04eb8f550a, 0xa5757bca84777f2b, 0xd3c2bf917b1192ea, 0x1989968c7935c607},
  {0xe1d62db2c86caa07, 0xb8ed617d8704c6b, 0x4e71934f60359a00, 0x25459aa434d50ff},
  {0x290a6ff9dd02df5e, 0x6e4c26ecf7984888, 0x8f5fb54612793d95, 0x31404beb90f0fdc8}
};

// Initial sponge state mainnet
static const Field _mainnet_iv_5w[SPONGE_WIDTH_5W] =
{
  {0x1bc46288607092ee, 0x679d1013fcd27af4, 0x2302588441a00b35, 0x52aa4180a0e1d3f},
  {0xf44d99f5d1788e7c, 0xa808f4bc1c5e8caa, 0xd3fd8806f5f3de6, 0x12ad0b5be60d68f1},
  {0x6928c9d83855c9d, 0x4b93a3d0d8209f22, 0xbbaea51d0f1f12e6, 0x62815b7ee55e6a8},
  {0x1fbd2d82dcfa2d, 0x78ec7156c609e43a, 0xf1e203a769275642, 0x3e15c2753ca6c1d},
  {0x6299f39409f35a31, 0x279b391979868236, 0x87b62f1b72d1deea, 0x3b44d1afce3a530d}
};