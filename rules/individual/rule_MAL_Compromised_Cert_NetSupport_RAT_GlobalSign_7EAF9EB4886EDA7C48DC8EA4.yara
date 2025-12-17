import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_GlobalSign_7EAF9EB4886EDA7C48DC8EA4 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-05"
      version             = "1.0"

      hash                = "98e12e68c45dc1b540c7f1c87e4293e3f0f0fecae98d3f49b60fdb4f646082d1"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Xuaony Lucid Dotaku Trading Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "7e:af:9e:b4:88:6e:da:7c:48:dc:8e:a4"
      cert_thumbprint     = "59CED3057E88B69EDD38587ACEE2BAEF92D32852"
      cert_valid_from     = "2024-07-05"
      cert_valid_to       = "2025-07-06"

      country             = "CN"
      state               = "Hubei"
      locality            = "Xiangyang"
      email               = "???"
      rdn_serial_number   = "91420600MA488H2M4C"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "7e:af:9e:b4:88:6e:da:7c:48:dc:8e:a4"
      )
}
