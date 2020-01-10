int jiekai(char *msg)
{
    //get key
    int len=strlen(msg);
	PCHAR env = (PCHAR) malloc(400);
	memset(env, 0, 400);    
    for (int i=0;i<344;i++)
        env[i]=msg[i];
    //printf("env=%s\n",env);
    PCHAR na="qMvq04wETHyfiYOw1yVLy9fpxaUJpzL3SXO10pL1yUB81lX8tQqvGTe1Bp4xLL9RRmpq9P9nGAkExbrjp66WoyanIxR4ml9k3Hd6CVse3BWTIJbrdPRV8cG7zVbAzFyFxqsUinDBzJwwqv7ENRLXwJ7QchfWoBjn2d9aPVFpcRzknIJLBXAAEGuZxCaV96Mpv94icEg1v50BWQjJhpZnPwYB5pstXOLG5brO5UhCXy6xUO6pUMoIVFGW6LPBW9PNtiomdOKl35sjLuEHwczvyKYNgPLH95Lg0EEieRyVgzX3cL0nPht9SMZzKg3wVgkColoaiWyjzVkLHSTPU6nDUFAD";
    PCHAR ea="H33";
    PCHAR nb="qMvq04wETHzGVQwqkh4BCUMSb0ch1R33thkUw8f5qFDARQCS0DvfpKQ7MRKWA4BjY9ZAyJY4jijhoxbXud5GM6LAtEETM7EkJpQdgNqYP9sO0sEXrlaar4gweC3syNvPuiLQCTaKU5sfFA1PI6iNUdNgkCsBk6Jl2gw5lEO5GxXp5IJlG3tpx9YAeITv3rYl0BN7sIn2g4A3O9eBjO1O84v2ixmqvSMVUqTIcx7vwbrzCBHeWTTq0ElajkB0ce9EoIxXplcddlYACz98ixBqMYWnQ0tVoGNg4PvBpBXBaVwhiLzREWbVsbDtncHJUKTJDVKsEAAEm5yumhMxz6tReUuz";
    PCHAR db="3zcLKduV0TggDe1c4RRt7I5qdWB0noENMBArmTIPcdhFgdybPbwUEgeFLDUPtz3KOry2gbmW0N5sgPE7ZSM4lWs7IS3WLw061rE2Kvw6cCKrKtdR1SHwtg37fqZ7tYnH5AtRl5bSuU6j4R9pg1DOKkUPT4JOJ9PcvDKZ8Y8vfN42sQEhrqgAMRsKFVk6Qj5pRhuYPGCB9EZwYebiUQnYSAuo02ceXzYDcVVXfL0R8hOopSMCDX3wMzVwBIMuiGFWQayJtWbJ9WWf9ZHB5X10vRN4HxjcDBQQjZqLg9HXwsB9CghLrGrc6eGvy1b8U3MYBPWvZrbnGvTyjQEd5hbBZUYL";
    PCHAR pk;
    decipher(env, nb, db, &pk);
	//printf("decode: %s\n", pk);
    const uint8_t *key2 = (uint8_t*)pk;
    
    //aesdecrypt
    PCHAR merge = (PCHAR) malloc(len-344);
	memset(merge, 0, len-344);
    for (int i=0;i<len-344;i++)
        merge[i]=msg[i+344];
    //printf("merge=:%s\n",merge);
    int len2=strlen(merge);
    uint8_t aaa[1000]={0};
	char a[4]="0x";
	char* b;
    for (int i=0; i<len2/2; i++)
    {
        a[2]=merge[2*i];
        a[3]=merge[2*i+1];
        aaa[i]=strtol(a,&b,16);
    }
    uint8_t plain2[500] = {0};
    aesDecrypt(key2, 16, aaa, plain2, len2/2);
    //printHex(plain2, len2/2, "after decryption:");
    //printf("output plain text\n");
    // for (int i = 0; i < len2/2; ++i) {
    //     printf("%c ", plain2[i]);
    // }
    
    char* mingwen = (char*) malloc(len2/2);
	for (int i = 0; i < len2/2; ++i) 
	{
		mingwen[i]=(unsigned char)plain2[i];
	}
	//printf("mingwen:%s,changdu:%ld\n",mingwen,strlen(mingwen));

    //decipher
	PCHAR ptext = (PCHAR) malloc(400);
	memset(ptext, 0, 400);
    for (int i=0;i<344;i++)
        ptext[i]=mingwen[i];
  PCHAR message = (PCHAR) malloc(400);
	memset(message, 0, 400);
	decipher(ptext, na, ea, &message);
	//printf("decode: %s\n", message);
    
    ///hash and verify
    int aa=0;
	PCHAR data = (PCHAR) malloc(len2-344);
    for (int k=0;k<len2-343;k++)
    {
        data[k]=mingwen[k+344];
    
    }
	aa=RSHash(data,strlen(data));
    int message1=atoi(message);
    if (message1==aa)
        printf("%s\n",data);
    else
        printf("校验失败。\n");
    return 0;
}

// int main()
// {
//     char a[]="Xd5eoNPjvGpooYPkixEnw5doRd0rJ6Vux9OXaX3LTuyDuYj4VnLKtxbkTPs7hgjjoCrYMImVuR12yl1Rvt1EEWJyiubQFuCgZpCL7Dhf19s3g2wfRDzTQh6cYUBdqkUXKE1zAawDt54ZK7ag9t4qmzltFhyqr6pxcliwwmFl2DQwW7YeHVaNW5XUCMQbu1nBSlA8BREEyf9lkFXnTJsbKXXcRp55mCuhw11xOeWvhCzYfLEQcia2A8DByflyRVmmGwh7VHqLjsH95fo6ert1C9h4Cml6JyPl1l4qIUcQZxs1MO0KF2XRb4ohVGxwdAlEowzZGQAh9zb3KHHfNDuC2ItXC00C3A5CA4B460207F65CC1E7F66C017E8C194BBCE40FC3293398EE98DCD7ADD601EF3A3582E54D8546460970BC7E1056672B0EA4D0756CC0471949FE842E2AB7402414EB8E0149B731CD076937EEDF9C212C1B0D5FB12CCFF357DC9F7B3F82617E4256312550B3E6AC1DE31803AA4BEA18D202C37129BE7DC56C516C64943F50D86B2A2130368953627746BC4F0BB601799264B1E002F2493A952747E6A385D467E14968FA346282F6DE5825378A13C5E674E985662BC327BB0EF980C70600E5B8AA694B705CFE80566F615D91516433F9AA088D82463C66AECCD5FCAEF9AB0DBED046E4A1A8B2163EB6806F459557AAF35DE55BF9AB7BFC43C46E5BDA2443D02CCF65D27030FC951ED97459A8FB6AD9C1B3528C0741A9B2E24C003556C51B186053D1D59E468C6260DCB67911872BCDAE8EA25E3BD77E7E8D39AD4230F1C6CE52D068455AF81919F0F3FF96E4E30FF6BC7C0F4590E36BAE8FCA26BB3B1826944BA8FBF51D0077819EEDC6B48BAA81066F414E3B57865E88265709BF10E183C";
//     jiekai(a);    
//     return 0;
// }
