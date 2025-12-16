import "pe"

rule MAL_Compromised_Cert_RMMLoader_GlobalSign_7744041A0EE72E8546C37940 {
   meta:
      description         = "Detects RMMLoader with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-06"
      version             = "1.0"

      hash                = "6869e503460bc04bfdc6ea36a3439b898711ec8aaf7176906464a5147672410c"
      malware             = "RMMLoader"
      malware_type        = "Unknown"
      malware_notes       = "This malicious signer build loads a legit RMM tool from dwservice.net"

      signer              = "Xingtai Yali Intelligent Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "77:44:04:1a:0e:e7:2e:85:46:c3:79:40"
      cert_thumbprint     = "3CCF15A6D26A6CF3813957D48FFB005BBCD5BC76"
      cert_valid_from     = "2025-05-06"
      cert_valid_to       = "2026-05-07"

      country             = "CN"
      state               = "河北省"
      locality            = "邢台市"
      email               = "???"
      rdn_serial_number   = "91130503MA0G685G99"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "77:44:04:1a:0e:e7:2e:85:46:c3:79:40"
      )
}
