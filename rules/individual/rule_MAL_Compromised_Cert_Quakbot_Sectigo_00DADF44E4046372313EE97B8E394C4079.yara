import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00DADF44E4046372313EE97B8E394C4079 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-09-08"
      version             = "1.0"

      hash                = "07dc705da27544ca4d232515c665dff2bbbf6b0ab49fd07c602e20d6a512b4af"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "Digital Capital Management Ireland Limited"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:da:df:44:e4:04:63:72:31:3e:e9:7b:8e:39:4c:40:79"
      cert_thumbprint     = "BE030FEFB88F9CFD0B67BE014662AE419E4936C0"
      cert_valid_from     = "2020-09-08"
      cert_valid_to       = "2021-09-08"

      country             = "IE"
      state               = "Kildare"
      locality            = "Naas"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:da:df:44:e4:04:63:72:31:3e:e9:7b:8e:39:4c:40:79"
      )
}
