import "pe"

rule MAL_Compromised_Cert_RemcosRAT_Sectigo_0082CB93593B658100CDD7A00C874287F2 {
   meta:
      description         = "Detects RemcosRAT with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-10-30"
      version             = "1.0"

      hash                = "75250cab773991fd76bf14b8c397b2f143100cf5b13f3213528167e43409a537"
      malware             = "RemcosRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Sportsonline24 B.V."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:82:cb:93:59:3b:65:81:00:cd:d7:a0:0c:87:42:87:f2"
      cert_thumbprint     = "39F27161BF3E8DDCB1AFB98822348EB28398F34B"
      cert_valid_from     = "2020-10-30"
      cert_valid_to       = "2021-10-30"

      country             = "NL"
      state               = "???"
      locality            = "Bloemendaal"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:82:cb:93:59:3b:65:81:00:cd:d7:a0:0c:87:42:87:f2"
      )
}
