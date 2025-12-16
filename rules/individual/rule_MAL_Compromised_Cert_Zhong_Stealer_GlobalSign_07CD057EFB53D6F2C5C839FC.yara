import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_GlobalSign_07CD057EFB53D6F2C5C839FC {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-28"
      version             = "1.0"

      hash                = "7a2adf0acbc37d870138bb65551e258a3d1bd4ab6bf50df0a7c66d770cc0f787"
      malware             = "Zhong Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware leverages cloud hosting to hold additional components. The components are TASLogin and its associated DLL: medium.com/@anyrun/zhong-stealer-analysis-new-malware-targeting-fintech-and-cryptocurrency-71d4a3cce42c"

      signer              = "Klimine Far Year Electronic Commerce Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "07:cd:05:7e:fb:53:d6:f2:c5:c8:39:fc"
      cert_thumbprint     = "FCAEEA9A9EBEC63DCC5E393DEB77DA0A2305166B"
      cert_valid_from     = "2024-05-28"
      cert_valid_to       = "2025-05-29"

      country             = "CN"
      state               = "Yunnan"
      locality            = "Kunming"
      email               = "???"
      rdn_serial_number   = "91530111MACH7ART91"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "07:cd:05:7e:fb:53:d6:f2:c5:c8:39:fc"
      )
}
