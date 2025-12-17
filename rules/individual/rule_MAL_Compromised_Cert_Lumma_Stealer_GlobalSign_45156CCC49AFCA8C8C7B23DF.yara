import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_GlobalSign_45156CCC49AFCA8C8C7B23DF {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-25"
      version             = "1.0"

      hash                = "0b8c1d7a910b0d9e747ebccc74b8bff20d33525bbdfc42a9b6044f6d4cf3815e"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "Pincoo Network Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "45:15:6c:cc:49:af:ca:8c:8c:7b:23:df"
      cert_thumbprint     = "416C21AF73942D925A5DAC5B932BF480902B89BE"
      cert_valid_from     = "2024-10-25"
      cert_valid_to       = "2025-10-26"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Shenzhen"
      email               = "???"
      rdn_serial_number   = "91440300596794584L"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "45:15:6c:cc:49:af:ca:8c:8c:7b:23:df"
      )
}
