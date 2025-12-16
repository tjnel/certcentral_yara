import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_GlobalSign_2B8D90A5626F4D697A670DF5 {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-06"
      version             = "1.0"

      hash                = "b7526c45705bcb8b469178f868e1112d972010b48402da4b0396a2824db52049"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "ForSun COWS BlackCoin Handel Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "2b:8d:90:a5:62:6f:4d:69:7a:67:0d:f5"
      cert_thumbprint     = "58E3746459129080B60C90D4965E40FCA1D9996A"
      cert_valid_from     = "2024-05-06"
      cert_valid_to       = "2025-04-27"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Foshan"
      email               = "???"
      rdn_serial_number   = "91440604MACKU2FD81"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "2b:8d:90:a5:62:6f:4d:69:7a:67:0d:f5"
      )
}
