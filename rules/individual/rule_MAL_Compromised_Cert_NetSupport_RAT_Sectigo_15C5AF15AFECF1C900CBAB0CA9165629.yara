import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_Sectigo_15C5AF15AFECF1C900CBAB0CA9165629 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-03-20"
      version             = "1.0"

      hash                = "2ae575f006fc418c72a55ec5fdc26bc821aa3929114ee979b7065bf5072c488f"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Kompaniya Auttek"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "15:c5:af:15:af:ec:f1:c9:00:cb:ab:0c:a9:16:56:29"
      cert_thumbprint     = "69735EC138C555D9A0D410C450D8BCC7C222E104"
      cert_valid_from     = "2020-03-20"
      cert_valid_to       = "2021-03-20"

      country             = "RU"
      state               = "Sankt-Peterburg"
      locality            = "Sankt-Peterburg"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "15:c5:af:15:af:ec:f1:c9:00:cb:ab:0c:a9:16:56:29"
      )
}
