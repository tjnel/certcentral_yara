import "pe"

rule MAL_Compromised_Cert_FakeZabbix_Sectigo_00FEA7AAE8DAD9370F4E82DBC2EBB0F916 {
   meta:
      description         = "Detects FakeZabbix with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-17"
      version             = "1.0"

      hash                = "7de52b73d0f039d4b64a436e285086cf828821d602016bcb2ac06299296e1f64"
      malware             = "FakeZabbix"
      malware_type        = "Unknown"
      malware_notes       = "Malicious installer impersonating Zabbix. Related: zabbxsoftware[.]com"

      signer              = "Xiamen Xinke Youxuan Software Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:fe:a7:aa:e8:da:d9:37:0f:4e:82:db:c2:eb:b0:f9:16"
      cert_thumbprint     = "8951FBA525F85BD0D631D5AB086780AD48655D11"
      cert_valid_from     = "2025-12-17"
      cert_valid_to       = "2026-12-17"

      country             = "CN"
      state               = "Fujian Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91350206MACT06NY6P"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:fe:a7:aa:e8:da:d9:37:0f:4e:82:db:c2:eb:b0:f9:16"
      )
}
