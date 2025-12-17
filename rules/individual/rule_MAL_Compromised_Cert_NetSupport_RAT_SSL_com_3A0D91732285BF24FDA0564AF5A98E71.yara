import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_SSL_com_3A0D91732285BF24FDA0564AF5A98E71 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-01-22"
      version             = "1.0"

      hash                = "980fcb6365092cd752934417abb0f2a95bca452c58856240157107e70c1d754d"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Changsha Ruike Hotel Management Co., Ltd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "3a:0d:91:73:22:85:bf:24:fd:a0:56:4a:f5:a9:8e:71"
      cert_thumbprint     = "2EA4B7DCF74AF6E4F8F27F5FBBEBAC033661A126"
      cert_valid_from     = "2024-01-22"
      cert_valid_to       = "2025-01-21"

      country             = "CN"
      state               = "Hunan"
      locality            = "Changsha"
      email               = "???"
      rdn_serial_number   = "91430104MA4QAQW82U"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "3a:0d:91:73:22:85:bf:24:fd:a0:56:4a:f5:a9:8e:71"
      )
}
