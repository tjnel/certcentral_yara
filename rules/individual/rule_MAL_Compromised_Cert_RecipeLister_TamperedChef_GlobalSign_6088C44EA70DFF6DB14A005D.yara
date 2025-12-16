import "pe"

rule MAL_Compromised_Cert_RecipeLister_TamperedChef_GlobalSign_6088C44EA70DFF6DB14A005D {
   meta:
      description         = "Detects RecipeLister,TamperedChef with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-06"
      version             = "1.0"

      hash                = "d8bff72de51213510004a2652b9e31b48a25e2eb0d7184fab4ef9014fc85e145"
      malware             = "RecipeLister,TamperedChef"
      malware_type        = "Backdoor"
      malware_notes       = "This malware was downloaded by advertisements for a Recipe application. The recipes contained hidden characters that could be decoded by the application. See the following for more details: https://www.bluevoyant.com/blog/recipelister-a-recipe-for-disaster"

      signer              = "IT BRIDGE CONNECT LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "60:88:c4:4e:a7:0d:ff:6d:b1:4a:00:5d"
      cert_thumbprint     = "4DC75B08FE34B0A4E8040C7EBA65783B17B75E06"
      cert_valid_from     = "2024-12-06"
      cert_valid_to       = "2025-12-07"

      country             = "UA"
      state               = "Kyiv"
      locality            = "Kyiv"
      email               = "???"
      rdn_serial_number   = "45342266"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "60:88:c4:4e:a7:0d:ff:6d:b1:4a:00:5d"
      )
}
