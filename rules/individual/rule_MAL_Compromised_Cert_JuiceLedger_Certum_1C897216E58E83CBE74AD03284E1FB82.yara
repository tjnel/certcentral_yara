import "pe"

rule MAL_Compromised_Cert_JuiceLedger_Certum_1C897216E58E83CBE74AD03284E1FB82 {
   meta:
      description         = "Detects JuiceLedger with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-12-10"
      version             = "1.0"

      hash                = "a50bcbf0ef744f6b7780685cfd2f41a13be4c921d4b401384efd85c6109d7c00"
      malware             = "JuiceLedger"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "M-Trans Maciej Caban"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "1c:89:72:16:e5:8e:83:cb:e7:4a:d0:32:84:e1:fb:82"
      cert_thumbprint     = "13CFDF20DFA846C94358DBAC6A3802DC0671EAB2"
      cert_valid_from     = "2021-12-10"
      cert_valid_to       = "2022-12-10"

      country             = "PL"
      state               = "łódzkie"
      locality            = "Skierniewice"
      email               = "???"
      rdn_serial_number   = "389470690"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "1c:89:72:16:e5:8e:83:cb:e7:4a:d0:32:84:e1:fb:82"
      )
}
