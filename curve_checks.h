// curve_checks.h - elliptic curve unit tests
//
//    These constants were generated from the Mina c-reference-signer

#pragma once

#include "crypto.h"

#define THROW(x) fprintf(stderr, "\n!! FAILED %s() at %s:%d !!\n\n", \
                         __FUNCTION__, __FILE__, __LINE__); \
                 return false;

#define EPOCHS 5

// Test scalars
static const Scalar S[5][2] = {
    {
        { 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, },
        { 0x44fcabdbb1cf694d, 0x684dd9a4c96a8110, 0x969c70100bd2aa4e, 0x2a0893db8c6f65cc, },
    },
    {
        { 0xbc7a8ad5f3ab5d23, 0xf75c20a07ece0bd5, 0x4e6a57d2af673850, 0x1d9c6e375cfe61d3, },
        { 0x3ecbc4a0bff2f00c, 0xb3a40181b69c8483, 0x381194435d0aea46, 0x06bc4aaf54cd27e1, },
    },
    {
        { 0xe8886d65206f2a0d, 0x7b840421c506d966, 0x3b623c2fb6522ba7, 0x266a173a74bdb777, },
        { 0x44541e516a9f81c0, 0x930aca12d4eedfd8, 0x4d36b841261f918d, 0x346da3a1e5c23c37, },
    },
    {
        { 0xe4daddfffc539e1d, 0x92675d03b3663fc7, 0x1c1d00377dd7d8b0, 0x097b64292f62d5a5, },
        { 0xde51c99c8f8409ac, 0xba781d2a7b31e232, 0x2be09b2bd52c50b7, 0x3d6dee21de6b178c, },
    },
    {
        { 0x2630f970eb10afbc, 0xefac1687510a1b4a, 0xf5c2413c82e36d95, 0x3467c0a5bb9232f6, },
        { 0x560131585ba798aa, 0x42552c81ea411721, 0x3de21c7f429694bc, 0x3bbc83d48e43a64c, },
    },
};

// Test curve points
static const Affine A[5][3] = {
    {
        {
            { 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,  },
            { 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,  },
        },
        {
            { 0x44a1d4abd1a63bd7, 0xfef6dc8872cdfbb3, 0x85e57317f8374d03, 0x1c0ab58288fbf0e1,  },
            { 0x84c10f2e7f5022d4, 0xe42b44568608892b, 0xc5f5a3ded3a09096, 0x0fc4ef0f51abfeb4,  },
        },
        {
            { 0x5e034ff41aeb4c3d, 0x015b1e4e207ee266, 0x0a780c903c970489, 0x3a6f66a85edb5be7,  },
            { 0x624216681c1502f1, 0x1bb89937012135fb, 0x2a1bbcd2a254d40b, 0x0a8439b12da42c3f,  },
        },
    },
    {
        {
            { 0x5e4326c50fb5af41, 0xe745c107771c9020, 0x0c8cfa0d6fb554d0, 0x32a98b49d6135c8b,  },
            { 0x241cb398efedf8ba, 0x7eea05caab8ba6f9, 0x087bee3ca0a3a6de, 0x353e9427934cf6cb,  },
        },
        {
            { 0xd0385516ddf59065, 0x36039de5ef9a4bf4, 0x19b665f5dd9a65a2, 0x0789e02e66ed7992,  },
            { 0x848a8d03a59bd5f8, 0x3e61d5e0b00aa69c, 0xd13bd1424de90d1d, 0x35b55f1fad2eff2f,  },
        },
        {
            { 0xb6f1cd1e33b1e9ad, 0x222a62094b663066, 0x666fffd462d287fc, 0x0e83076a95550a06,  },
            { 0xb7e468783afdf63f, 0x89164490e717749f, 0x40abaf0c2c001279, 0x0c823071308fe3e6,  },
        },
    },
    {
        {
            { 0x553318851cfc95fe, 0x5bf9f9b401511c87, 0x318a2899280bdb84, 0x097372cddf242a01,  },
            { 0x2c70d1bb636cf7db, 0x672091e51f32fe01, 0xd48c4b93a2eb3595, 0x1f6c712398f51766,  },
        },
        {
            { 0x5b35b6f379f79dce, 0x11d883976d2f9f5f, 0xd99c184faaab3e18, 0x0ba27917c9e6abde,  },
            { 0xf6e26f72d4cf6dfe, 0x429d992d04764436, 0x7be989343be3121a, 0x215c65b53f96ddbc,  },
        },
        {
            { 0x7819a2493609849c, 0xd6d8790d8f6cc542, 0x9e8400ed462f4e30, 0x0d633f191fbaa4ee,  },
            { 0x887325d13a3050e7, 0x5b02db6cee45002a, 0xaff0063539f7f25a, 0x14afb7ef8f379c40,  },
        },
    },
    {
        {
            { 0x7dec5e04aac3bde3, 0xc138b04ef1721b8b, 0x652c537bb7d2d3d9, 0x340c45a42d66c214,  },
            { 0x849d3d38a51a078d, 0xa886bcdcbad5f4a4, 0x287c33a151cc1978, 0x3756bc52cdd0b57d,  },
        },
        {
            { 0x413341fd86cbe262, 0xd97e6516a0342546, 0xbf54ddba8f2dd75b, 0x3b015d1344b0bbae,  },
            { 0xa92f27ff80100162, 0x8d418ab22f558b24, 0x573387adc9655403, 0x2731ac2ee97f0b62,  },
        },
        {
            { 0x7b8ebdd1fa093ef5, 0x3c80c1b0296e07eb, 0x49c6c52df071dc6b, 0x11a24036a43126f1,  },
            { 0x3e02ea2007496d5f, 0x81fd8328d2360ccc, 0x73aa6a119bad9d0c, 0x1c3f0b60c7d732e9,  },
        },
    },
    {
        {
            { 0x6369e0ab65026040, 0x39e50f95307c08ad, 0xe124618b693343ec, 0x196caaa34ec991e7,  },
            { 0x8a19a58fc876ae9d, 0x7b622ae21b12bce8, 0x0d4460d7b89ee594, 0x2c9c7e0f9cb4463b,  },
        },
        {
            { 0xef549a00ddca0dd3, 0x08b4ea303f03de7a, 0x45966a8ac0311a74, 0x04ecd3238a49c4d2,  },
            { 0x4c0529c3ec19c5a7, 0x5f8f9b78755a6809, 0x40deeb9758c099c9, 0x066e36c7e5eefbe1,  },
        },
        {
            { 0xc2967ff8f1438147, 0xdc4db4505780de9b, 0x6a2f63c4f34dc6c6, 0x2794fc4ec956ead1,  },
            { 0x43fee8cab1ea1b28, 0x7de1b5af30a6ee9a, 0x64957ce7f7cc2ddb, 0x1424440eafc5ba7c,  },
        },
    },
};

// Target outputs
static const Affine T[5][5] = {
    {
        {
            { 0x44a1d4abd1a63bd7, 0xfef6dc8872cdfbb3, 0x85e57317f8374d03, 0x1c0ab58288fbf0e1,  },
            { 0x84c10f2e7f5022d4, 0xe42b44568608892b, 0xc5f5a3ded3a09096, 0x0fc4ef0f51abfeb4,  },
        },
        {
            { 0x44a1d4abd1a63bd7, 0xfef6dc8872cdfbb3, 0x85e57317f8374d03, 0x1c0ab58288fbf0e1,  },
            { 0x84c10f2e7f5022d4, 0xe42b44568608892b, 0xc5f5a3ded3a09096, 0x0fc4ef0f51abfeb4,  },
        },
        {
            { 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,  },
            { 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,  },
        },
        {
            { 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,  },
            { 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,  },
        },
        {
            { 0x0572ca59c20858b0, 0x510d404e4326b38d, 0x882ae6e335f7b516, 0x178551c540dcc522,  },
            { 0xaa1cd6e03fe728ab, 0x68f8db3633865da4, 0x5c65fec7cb01eef7, 0x2db8a476bf00dd2f,  },
        },
    },
    {
        {
            { 0xc17e99525bf34ddb, 0xd7e1088dffdaee15, 0x6f815919f118dec6, 0x307fd699ab2a8297,  },
            { 0xdf5a95d4abe65e25, 0x8c7a138f7371f4d5, 0x94dbfc51af3c5d6a, 0x3d062c65e0fedf1b,  },
        },
        {
            { 0xc17e99525bf34ddb, 0xd7e1088dffdaee15, 0x6f815919f118dec6, 0x307fd699ab2a8297,  },
            { 0xdf5a95d4abe65e25, 0x8c7a138f7371f4d5, 0x94dbfc51af3c5d6a, 0x3d062c65e0fedf1b,  },
        },
        {
            { 0x1ae1f1da7901585f, 0x09f09df05c1a8c55, 0x9469b1580a1caecc, 0x3b477678e9f9bea2,  },
            { 0x79471589a10a14c4, 0x1c09515647f040ae, 0x2279716461da5d56, 0x002a0153983eb8a5,  },
        },
        {
            { 0x5e4326c50fb5af41, 0xe745c107771c9020, 0x0c8cfa0d6fb554d0, 0x32a98b49d6135c8b,  },
            { 0x75107d5410120747, 0xa35c93315dc15222, 0xf78411c35f5c5921, 0x0ac16bd86cb30934,  },
        },
        {
            { 0x748d9c0d4cbc8801, 0xaa788d19e91caf6e, 0x6038ed92064a3ab4, 0x29cc2372f4a28ca7,  },
            { 0x9f76434395caed0a, 0xf826718aa1b2f1f6, 0x6b26023925d60e5e, 0x28add1d7c9bdb126,  },
        },
    },
    {
        {
            { 0x3c302568451dccae, 0xf7a448b3adfe384b, 0x4f0ca174c6ffef37, 0x28d4504d170e7cb3,  },
            { 0x6730040e84773376, 0xd6506a7932e07dd7, 0xc9a614eb04eca6f2, 0x3814e9fa39dfd13c,  },
        },
        {
            { 0x3c302568451dccae, 0xf7a448b3adfe384b, 0x4f0ca174c6ffef37, 0x28d4504d170e7cb3,  },
            { 0x6730040e84773376, 0xd6506a7932e07dd7, 0xc9a614eb04eca6f2, 0x3814e9fa39dfd13c,  },
        },
        {
            { 0xaa9cfa75f0e3b6ae, 0x73cfce1b47585d32, 0x1d1e44dbdc5ec6e3, 0x3a73eb10b8f1129e,  },
            { 0x10144ac0024a66a4, 0xbcb41fc7a61ce70c, 0xf75c0701186d58f9, 0x017d6e135ebabbba,  },
        },
        {
            { 0x553318851cfc95fe, 0x5bf9f9b401511c87, 0x318a2899280bdb84, 0x097372cddf242a01,  },
            { 0x6cbc5f319c930826, 0xbb260716ea19fb1a, 0x2b73b46c5d14ca6a, 0x20938edc670ae899,  },
        },
        {
            { 0xdd068acf740859dc, 0xa4ebe7ec50539f38, 0x9d2e6b67e05cd2b0, 0x2145560aa3250cc2,  },
            { 0x14b8b4dff750f4cf, 0x3fc747c6b8c03513, 0x58685761a08cf4ed, 0x3c9cc33069dd5a37,  },
        },
    },
    {
        {
            { 0xe423ac9eff88c074, 0x1572c26387aa1150, 0xe001f9fd52c12c60, 0x133f15f61c3787a9,  },
            { 0x7bf1208ab45aac24, 0x761ce9d05948a648, 0x2ab07227afc5525d, 0x163684490bad2f53,  },
        },
        {
            { 0xe423ac9eff88c074, 0x1572c26387aa1150, 0xe001f9fd52c12c60, 0x133f15f61c3787a9,  },
            { 0x7bf1208ab45aac24, 0x761ce9d05948a648, 0x2ab07227afc5525d, 0x163684490bad2f53,  },
        },
        {
            { 0x45af43a125eb43d8, 0x26bcb3085bbbd05f, 0x74bc85df902ff69c, 0x1807311ea8e29279,  },
            { 0x25a56558297274a0, 0xaa2455cfad01648d, 0x4d1fde1da8947f29, 0x2f44fc51ee52bca2,  },
        },
        {
            { 0x7dec5e04aac3bde3, 0xc138b04ef1721b8b, 0x652c537bb7d2d3d9, 0x340c45a42d66c214,  },
            { 0x148ff3b45ae5f874, 0x79bfdc1f4e770477, 0xd783cc5eae33e687, 0x08a943ad322f4a82,  },
        },
        {
            { 0xd61c79e2c23ce85a, 0xf10f343dabb3433e, 0x121f292c9176bb71, 0x2b68d09b387d76a8,  },
            { 0xd2367a51254bdb6b, 0xa756fecf50ca69dd, 0x24f28888b96049c0, 0x0fbda5678e17b21b,  },
        },
    },
    {
        {
            { 0x6f5e60a47208e090, 0x9ad8f9bd82ada3f1, 0xd055f1e3d2e90343, 0x2b78ba8edbdd24b8,  },
            { 0xd9d7391f0632ae00, 0xb6c8b1a0c28500cf, 0x887f2362fd2d195f, 0x1dd47810a6eb091f,  },
        },
        {
            { 0x6f5e60a47208e090, 0x9ad8f9bd82ada3f1, 0xd055f1e3d2e90343, 0x2b78ba8edbdd24b8,  },
            { 0xd9d7391f0632ae00, 0xb6c8b1a0c28500cf, 0x887f2362fd2d195f, 0x1dd47810a6eb091f,  },
        },
        {
            { 0xadb8ada3ff4c1862, 0xc37aec5f5151f29d, 0x6be3f892ad450a78, 0x38d0682f0e6fc1e8,  },
            { 0x86f43fca7c79f4dc, 0xb7da3a823f15974e, 0x3e8320b73bf0bc22, 0x30fe62526b1f5473,  },
        },
        {
            { 0x6369e0ab65026040, 0x39e50f95307c08ad, 0xe124618b693343ec, 0x196caaa34ec991e7,  },
            { 0x0f138b5d37895164, 0xa6e46e19ee3a3c33, 0xf2bb9f2847611a6b, 0x136381f0634bb9c4,  },
        },
        {
            { 0x654d731b146c3ee5, 0x1c120cb32ff7139e, 0x145376f65e2e17b8, 0x21b5b0ad9b214cd2,  },
            { 0xcc63e744cea3c0c6, 0xc45b4f8c5ca0f6ba, 0xcce752babb44aee4, 0x25e3b1d205bb0e6e,  },
        },
    },
};

bool curve_checks(void);
