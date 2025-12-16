import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_5B440A47E8CE3DD202271E5C7A666C78 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-09-08"
      version             = "1.0"

      hash                = "f82299590f685b0915f2f18ad25c1d11ab35120d5055b1c06720b519ac2cb23f"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "Master Networking s.r.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "5b:44:0a:47:e8:ce:3d:d2:02:27:1e:5c:7a:66:6c:78"
      cert_thumbprint     = "2DBBBEDC7FD628132660C05EF3D1147E1194D8DD"
      cert_valid_from     = "2020-09-08"
      cert_valid_to       = "2021-09-08"

      country             = "CZ"
      state               = "Jihomoravský kraj"
      locality            = "Brno"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "5b:44:0a:47:e8:ce:3d:d2:02:27:1e:5c:7a:66:6c:78"
      )
}
