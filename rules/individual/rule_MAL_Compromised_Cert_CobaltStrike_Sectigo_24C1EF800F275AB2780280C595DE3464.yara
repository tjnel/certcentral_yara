import "pe"

rule MAL_Compromised_Cert_CobaltStrike_Sectigo_24C1EF800F275AB2780280C595DE3464 {
   meta:
      description         = "Detects CobaltStrike with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-03-03"
      version             = "1.0"

      hash                = "bf476d0296be27e3b75b2cad6330839d0f294b094a6d0d50b4cf62010fb17244"
      malware             = "CobaltStrike"
      malware_type        = "Remote access tool"
      malware_notes       = "A commercial red-teaming product which is weaponized by a wide range of cybercriminals: https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"

      signer              = "HOLGAN LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "24:c1:ef:80:0f:27:5a:b2:78:02:80:c5:95:de:34:64"
      cert_thumbprint     = "836B81154EB924FE741F50A21DB258DA9B264B85"
      cert_valid_from     = "2021-03-03"
      cert_valid_to       = "2022-03-03"

      country             = "GB"
      state               = "Oxfordshire"
      locality            = "Thame"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "24:c1:ef:80:0f:27:5a:b2:78:02:80:c5:95:de:34:64"
      )
}
