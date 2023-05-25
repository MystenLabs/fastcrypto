import { JWK } from "jwk-to-pem";

class TestVector {
    "jwt": string;
    "jwk": JWK;
    header?: any;
    payload?: any;
};

const GOOGLE: TestVector = { // From extension
    jwt: "eyJhbGciOiJSUzI1NiIsImtpZCI6ImM5YWZkYTM2ODJlYmYwOWViMzA1NWMxYzRiZDM5Yjc1MWZiZjgxOTUiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI1NzU1MTkyMDQyMzctbXNvcDllcDQ1dTJ1bzk4aGFwcW1uZ3Y4ZDg0cWRjOGsuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI1NzU1MTkyMDQyMzctbXNvcDllcDQ1dTJ1bzk4aGFwcW1uZ3Y4ZDg0cWRjOGsuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTA0NjM0NTIxNjczMDM1OTgzODMiLCJlbWFpbCI6IndhbmdxaWFveWkuam95QGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJub25jZSI6IkdDd3EyekN1cXRzYTFCaGFBYzJTRWx3VW9ZdjhqS2hFNnZzNlZtZXB1Mk0iLCJpYXQiOjE2ODMzMjMyNjksImV4cCI6MTY4MzMyNjg2OSwianRpIjoiMDEzMzA2YjY1MmY0Zjg1MjUxZTU1OGVhNGFhOWJkYWI3ZmQxNzk3ZiJ9.",
    jwk: {
        "e": "AQAB",
        "kty": "RSA",
        "n": "t0VFy4n4MGtbMWJKk5qfCY2WGBja2WSWQ2zsLziSx9p1QE0QgXtr1x85PnQYaYrAvOBiXm2mrxWnZ42MxaUUu9xyykTDxsNWHK--ufchdaqJwfqd5Ecu-tHvFkMIs2g39pmG8QfXJHKMqczKrvcHHJrpTqZuos1uhYM9gxOLVP8wTAUPNqa1caiLbsszUC7yaMO3LY1WLQST79Z8u5xttKXShXFv1CCNs8-7vQ1IB5DWQSR2um1KV4t42d31Un4-8cNiURx9HmJNJzOXbTG-vDeD6sapFf5OGDsCLO4YvzzkzTsYBIQy_p88qNX0a6AeU13enxhbasSc-ApPqlxBdQ"
    },
    header: {
        "alg": "RS256",
        "kid": "c9afda3682ebf09eb3055c1c4bd39b751fbf8195",
        "typ": "JWT"
    },
    payload: {
        "iss": "https://accounts.google.com",
        "azp": "575519204237-msop9ep45u2uo98hapqmngv8d84qdc8k.apps.googleusercontent.com",
        "aud": "575519204237-msop9ep45u2uo98hapqmngv8d84qdc8k.apps.googleusercontent.com",
        "sub": "110463452167303598383",
        "email": "wangqiaoyi.joy@gmail.com",
        "email_verified": true,
        "nonce": "GCwq2zCuqtsa1BhaAc2SElwUoYv8jKhE6vs6Vmepu2M",
        "iat": 1683323269,
        "exp": 1683326869,
        "jti": "013306b652f4f85251e558ea4aa9bdab7fd1797f"
    }
}

const FACEBOOK: TestVector = {
    jwt: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjhhYjM3MTc1MjdhZTQwMWRlNWRjMGRmNGY5ZjJmZTZkNjUwY2NhYWUifQ.eyJpc3MiOiJodHRwczpcL1wvd3d3LmZhY2Vib29rLmNvbSIsImF1ZCI6IjEyNDE1NTkzNjY3NTUyMTQiLCJzdWIiOiI3MDg1NjI2MTEwMDk1MjUiLCJpYXQiOjE2ODIwMDQ3OTcsImV4cCI6MTY4MjAwODM5NywianRpIjoiR3NFMy5iNTY2YmI4Mjg4ZTQ3ZTMxMjIwZDM3NzY4ZWJlMWM5NTIzOTM0YzYxZmE3ZjkzYWM3MWI3NTcxZjg5M2Q3NzZlIiwibm9uY2UiOiIxNjYzNzkxODgxMzkwODA2MDI2MTg3MDUyODkwMzk5NDAzODcyMTY2OTc5OTYxMzgwMzYwMTYxNjY3ODE1NTUxMjE4MTI3MzI4OTQ3NyIsImdpdmVuX25hbWUiOiJKb3kiLCJmYW1pbHlfbmFtZSI6IldhbmciLCJuYW1lIjoiSm95IFdhbmciLCJwaWN0dXJlIjoiaHR0cHM6XC9cL3BsYXRmb3JtLWxvb2thc2lkZS5mYnNieC5jb21cL3BsYXRmb3JtXC9wcm9maWxlcGljXC8_YXNpZD03MDg1NjI2MTEwMDk1MjUmaGVpZ2h0PTEwMCZ3aWR0aD0xMDAmZXh0PTE2ODQ1OTY3OTgmaGFzaD1BZVJJZ1JMX1hvb3FyZERpZE5ZIn0.taavbVRWSJYQAGVfADLb0Un1gHakURX1lbGO7wjOjRgOZxnoF_1fAOE9QoSftZPMpg4-WhYYl-sC0SxETX6rW9lULT7oNomuO8Jm0kgyxeITvi7oWK_QLt8VWJZPAM2ZP2-xEFR92juQKTnbsuAB14fl2gXKlt_QZDtAmi3Gno0By94E7bWmSPd1mQJA1M0GUu4LDNZe0_mGHEQ9ygamyQVfB9u3STTeb1HOfNKO3HXmwmTJRhdIuc_z96wWBf8-JR52d1gAL0MWL5my6yPyvqtpfti-8-jWYPUuR-KOzhdj-IsaGZMzgJUJZg7wg6z9_P2Uqn3Muh-BSzTNYxVYPQ",
    jwk: {
        "kty": "RSA", 
        "n": "xirBDhLBy2BlSheGTJx3_jWdUado6QHTD5_rZK3_26m02zCFGqkHbJJihDwwTdmpVanrw0cb_7OIlw0hZjVNPnjhPHnwy-zT1XYK7qAfVBD0wm9GJhGsAe5dWSCjee7U-uRHAijNYXBeQn5Oh2w1KCCDr6Ccgk65xk5cuMCanKtAf6yXzVnKZJyvBxSzZD4p0Bw8MSOzSXY5srvUSGuCeajV8D-IDaP4LEXWswLUJKD3DrOlKH8QHHUhnPHjXAUZId_PMttmK32TqkWJeL0sjJ2KT68QHXCgL2RDWCg_TiOM8yx_LVGpeg0mLaadw0UNVT_nfmH_1s1S9XVpEu42Xw", 
        "e": "AQAB"
    }
}

const GOOGLE_OLD: TestVector = { // from playground
    jwt: 'eyJhbGciOiJSUzI1NiIsImtpZCI6Ijk4NmVlOWEzYjc1MjBiNDk0ZGY1NGZlMzJlM2U1YzRjYTY4NWM4OWQiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI0MDc0MDg3MTgxOTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI0MDc0MDg3MTgxOTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTc5MTI3MzU2NTg1NDEzMzY2NDYiLCJhdF9oYXNoIjoicm9aYm11cUVXdmNHSThDR2N1SnJmUSIsImlhdCI6MTY3OTY3NDE0NSwiZXhwIjoxNjc5Njc3NzQ1fQ.G8cciXefORmYvdwrfVAO6DjDy7DUWe6NxyanGg4w7EQBu8Ab7PJAeXhU7HL5w_LtTgiLA3Ew07RRzuNuaFITvs_m9lIolxHOl0BZSyGIGlI9BRiBFQQK2OZ2b8xetWz3B1mezcwlrrQMgbLQI0puuaA6917h_3MjIgZu_bQkjQH3Lwl3kkZWp0W-PRuK20KAQneNFB9ehTvSeRkImIr5QlZU6LMb7M3rI_-gP6ePRryAN9UCGBASzNEYLaQz-eMIdYFw-WmqkesTX1IDLQT0n44BhG9-9mWIA6kNRSBo9FV89VGKvYION9PTDds1vsf5h3smBQZjourR2H5pLJ_MUA',
    jwk: {
        "e": "AQAB",
        "kty": "RSA",
        "n": "onb-s1Mvbpti06Sp-ZsHH5eeJxdvMhRgfmx5zK7cVlcAajI_0rKu8ylU2CkfgPlMe9-8W5ayozm1h2yx2ToS7P7qoR1sMINXbKxobu8xy9zOBuFAr3WvEoor6lo0Qp747_4bN1sVU6GBEBEXLjb8vHN-o_yoBv8NSB_yP7XbEaS3U5MJ4V2s5o7LziIIRP9PtzF0m3kWm7DuyEzGvCaW8s9bOiMd3eZyXXyfKjlBB727eBXgwqcV-PttECRw6JCLO-11__lmqfKIj5CBw18Pb4ZrNwBa-XrGXfHSSAJXFkR4LR7Bj24sWzlOcKXN2Ew4h3WDJfxtN_StNSYoagyaFQ"
    }
}

const TWITCH: TestVector = {
    jwt: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJhdWQiOiJkMzFpY3FsNmw4eHpwYTdlZjMxenR4eXNzNDZvY2siLCJleHAiOjE2ODMzMjQyNjgsImlhdCI6MTY4MzMyMzM2OCwiaXNzIjoiaHR0cHM6Ly9pZC50d2l0Y2gudHYvb2F1dGgyIiwic3ViIjoiOTA0NDQ4NjkyIiwiZW1haWwiOiJ3YW5nam95am95MjAxOUBnbWFpbC5jb20iLCJub25jZSI6IkdDd3EyekN1cXRzYTFCaGFBYzJTRWx3VW9ZdjhqS2hFNnZzNlZtZXB1Mk0ifQ.",
    jwk: {
        "e": "AQAB",
        "kty": "RSA",
        "n": "6lq9MQ-q6hcxr7kOUp-tHlHtdcDsVLwVIw13iXUCvuDOeCi0VSuxCCUY6UmMjy53dX00ih2E4Y4UvlrmmurK0eG26b-HMNNAvCGsVXHU3RcRhVoHDaOwHwU72j7bpHn9XbP3Q3jebX6KIfNbei2MiR0Wyb8RZHE-aZhRYO8_-k9G2GycTpvc-2GBsP8VHLUKKfAs2B6sW3q3ymU6M0L-cFXkZ9fHkn9ejs-sqZPhMJxtBPBxoUIUQFTgv4VXTSv914f_YkNw-EjuwbgwXMvpyr06EyfImxHoxsZkFYB-qBYHtaMxTnFsZBr6fn8Ha2JqT1hoP7Z5r5wxDu3GQhKkHw"
    },
    header: {
        "alg": "RS256",
        "typ": "JWT",
        "kid": "1"
    },
    payload: {
        "aud": "d31icql6l8xzpa7ef31ztxyss46ock",
        "exp": 1683324268,
        "iat": 1683323368,
        "iss": "https://id.twitch.tv/oauth2",
        "sub": "904448692",
        "email": "wangjoyjoy2019@gmail.com",
        "nonce": "GCwq2zCuqtsa1BhaAc2SElwUoYv8jKhE6vs6Vmepu2M"
    }
}

export {
    GOOGLE,
    GOOGLE_OLD,
    FACEBOOK,
    TWITCH
}