{-# LANGUAGE CPP #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE ViewPatterns #-}

#ifdef VERSION_aeson
{-# LANGUAGE StandaloneDeriving #-}
#endif

-- |
-- Module: Network.HostAddress
-- Copyright: Copyright © 2020 Lars Kuhtz <lakuhtz@gmail.com>
-- License: MIT
-- Maintainer: Lars Kuhtz <lakuhtz@gmail.com>
-- Stability: experimental
--
-- Host addresses as described in RFC2396 section 3.2.2 with additional consideration of
--
-- * RFC1123 (additional restrictions for hostnames),
-- * RFC1034 (disambiguate domain names and IPv4 addresses),
-- * RFC4291 (parsing of IPv6 addresses), and
-- * RFC3986 and RFC5952 (IPv6 literals within host addresses).
--
-- Port numbers must be within the range @[0,2^16-1]@.
--
-- All hostnames are considered fully qualified and thus the final dot is
-- omitted.
--
-- For hostnames we follow the specification for "Server-based Naming Authority"
-- for URIs from RFC2396 section 3.2.2.:
--
-- @
--      hostport      = host [ ":" port ]
--      host          = hostname | IPv4address
--      hostname      = *( domainlabel "." ) toplabel [ "." ]
--      domainlabel   = alphanum | alphanum *( alphanum | "-" ) alphanum
--      toplabel      = alpha | alpha *( alphanum | "-" ) alphanum
--
--      IPv4address   = 1*digit "." 1*digit "." 1*digit "." 1*digit
--      port          = *digit
-- @
--
-- @1*digit@ designates the decimal representation of an octet. The specification
-- takes the form of hostnames from section 2.1 RFC1123, but limiting the
-- rightmost (top-most) label to the from given in section 3 of RFC1034, which
-- allows to disambiguate domain names and IPv4 addresses.
--
-- IPv6 Addresses are partially supported. IPv6 address are parsed as described
-- in RFC4291, but embedding of IPv4 addresses is not supported. IPv6 addresses
-- are printed exactly as they where parsed. No normalization is performed. In
-- particular the recommendations from RFC5952 are not considered. For host
-- addresses RFC3986 and RFC5952 are followed by requiring that IPv6 literals
-- are enclosed in square brackets. Anything else from RFC3986, which is
-- concerning URIs is ignored.
--
-- Additional restriction for hostname apply from RFC1123: labels must have not
-- more than 63 octets, letters are case-insensitive. The maximum length must not
-- exceed 254 octets, excluding the (optional) terminating dot.
--
-- See <https://cs.uwaterloo.ca/twiki/view/CF/HostNamingRules> for an extensive
-- overview of different standards for host names.
--
-- Non-ascii characters are encoded via Punycode and are of no concern in this
-- implementation.
--
module Network.HostAddress
(
-- * Port Numbers
  Port
, portToText
, portFromText
, readPortBytes

-- * Hostnames
, Hostname
, hostnameBytes
, readHostnameBytes
, hostnameToText
, hostnameFromText
, unsafeHostnameFromText

-- ** Pattern Synonyms
, IPv4
, IPv6
, pattern HostName
, pattern HostIPv4
, pattern HostIPv6

-- ** Special Host Names
, localhost
, localhostIPv4
, localhostIPv6
, anyIpv4
, broadcast
, loopback
, isReservedHostname
, isPrivateHostname
, isLocalIp

-- * HostAddresses
, HostAddress(..)
, hostAddressPort
, hostAddressHost
, hostAddressBytes
, readHostAddressBytes
, hostAddressToText
, hostAddressFromText
, unsafeHostAddressFromText

-- ** Special Host Addresses
, isPrivateHostAddress
, isReservedHostAddress

#ifdef VERSION_configuration_tools
-- * Configuration Tools Support
, pPort
, pHostname
, pHostAddress
, pHostAddress'
#endif

#ifdef VERSION_QuickCheck
-- * Arbitrary Values
, arbitraryPort
, arbitraryDomainName
, arbitraryIpV4
, arbitraryIpV6
, arbitraryHostname
, arbitraryHostAddress

-- * Properties
, properties
#endif
) where

#ifdef VERSION_configuration_tools
import Configuration.Utils hiding ((<?>), (<|>), FromJSON, ToJSON)
#endif

import Control.Applicative
import Control.DeepSeq (NFData)
import Control.Monad
import Control.Monad.Catch

#ifdef VERSION_aeson
import Data.Aeson hiding ((<?>))
#endif

import Data.Attoparsec.ByteString.Char8
#ifdef VERSION_configuration_tools
import Data.Bifunctor
#endif
import qualified Data.ByteString.Char8 as B8
import qualified Data.CaseInsensitive as CI
import Data.Hashable (Hashable(..))
import Data.IP hiding (IPv4, IPv6)
import qualified Data.IP as IP (IPv4)
#ifdef VERSION_QuickCheck
import qualified Data.List as L
#endif
import Data.Maybe
import Data.String
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Data.Word (Word16, Word8)

import GHC.Generics (Generic)
import GHC.Stack (HasCallStack)

import Lens.Micro.TH (makeLenses)

#ifdef VERSION_configuration_tools
import qualified Options.Applicative as O
#endif

#ifdef VERSION_QuickCheck
import Test.QuickCheck
#endif

-- -------------------------------------------------------------------------- --
-- Utils

sshow :: Show a => IsString b => a -> b
sshow = fromString . show
{-# INLINE sshow #-}

fromJuste :: HasCallStack => Maybe a -> a
fromJuste = fromJust
{-# INLINE fromJuste #-}

int :: Integral a => Num b  => a -> b
int = fromIntegral
{-# INLINE int #-}

newtype HostAddressParserException = HostAddressParserException T.Text
    deriving (Show, Eq, Ord, Generic)
    deriving anyclass (Hashable)
    deriving newtype (NFData)

instance Exception HostAddressParserException

-- -------------------------------------------------------------------------- --
-- Internal Parsers

data HostType = HostTypeName | HostTypeIPv4 | HostTypeIPv6
    deriving (Show, Eq, Ord, Generic, Hashable)

hostParser :: Parser HostType
hostParser
    = HostTypeName <$ hostNameParser
    <|> HostTypeIPv4 <$ ipV4Parser
    <|> HostTypeIPv6 <$ ipV6Parser
    <?> "host"

hostNameParser :: Parser ()
hostNameParser = ()
    <$ many' (domainlabel <* ".") <* toplabel
    <?> "hostname"
  where
    domainlabel = ()
        <$ alphanum <* optional labelTail
        <?> "domainlabel"

    toplabel = ()
        <$ alpha <* optional labelTail
        <?> "toplabel"

    labelTail = alphanumhyphen >>= \case
        '-' -> labelTail
        _ -> () <$ optional labelTail

    alpha = satisfy isAlpha_ascii
        <?> "alpha"

    alphanum = satisfy (\c -> isAlpha_ascii c || isDigit c)
        <?> "alphanum"

    alphanumhyphen = satisfy (\c -> isAlpha_ascii c || isDigit c || c == '-')
        <?> "alphahumhypen"

type IPv4 =  (Word8, Word8, Word8, Word8)

ipV4Parser :: Parser IPv4
ipV4Parser = (,,,)
    <$> (octet <* ".") <*> (octet <* ".") <*> (octet <* ".") <*> octet
    <?> "ipv4address"
  where
    octet :: Parser Word8
    octet = (decimal >>= \(d :: Integer) -> int d <$ guard (d < 256))
        <?> "octet"

type IPv6 = [Maybe Word16]

ipV6Parser :: Parser IPv6
ipV6Parser = p0
  where
    p0 = l1 <$> elision <* endOfInput
        <|> l3 <$> elision <*> h16 <*> p2 6
        <|> l2 <$> h16 <*> p1 7
        <?> "IPv6address"

    p1 :: Int -> Parser [Maybe Word16]
    p1 0 = l0 <$ endOfInput <?> "IPv6 prefix: too many segments"
    p1 i = l1 <$> elision <* endOfInput
        <|> l3 <$> elision <*> h16 <*> p2 (i - 2)
        <|> l2 <$ ":" <*> h16 <*> p1 (i - 1)
        <?> "IPv6 prefix"

    p2 :: Int -> Parser [Maybe Word16]
    p2 0 = l0 <$ endOfInput <?> "IPv6 suffix: too many segments"
    p2 i = l2 <$ ":" <*> h16 <*> p2 (i - 1)
        <|> l0 <$ endOfInput
        <?> "IPv6 suffix"

    elision :: Parser (Maybe Word16)
    elision = Nothing <$ "::"

    h16 :: Parser (Maybe Word16)
    h16 = Just <$> do
        h <- hexadecimal @Integer
        guard $ h < int (maxBound @Word16)
        return $! int h
        <?> "h16"

    l0 = []
    l1 = pure
    l2 = (:)
    l3 a b t = a:b:t

portParser :: Parser Port
portParser = Port
    <$> (decimal >>= \(d :: Integer) -> int d <$ guard (d < 2^(16 :: Int)))
    <?> "port"

parseBytes :: MonadThrow m => T.Text -> Parser a -> B8.ByteString -> m a
parseBytes name parser b = either (throwM . HostAddressParserException . msg) return
    $ parseOnly (parser <* endOfInput) b
  where
    msg e = "Failed to parse " <> sshow b <> " as " <> name <> ": "
        <> T.pack e

parseIPv4 :: MonadThrow m => B8.ByteString -> m IPv4
parseIPv4 = parseBytes "IPv4" (ipV4Parser <* endOfInput)
{-# INLINE parseIPv4 #-}

parseIPv6 :: MonadThrow m => B8.ByteString -> m IPv6
parseIPv6 = parseBytes "IPv6" (ipV6Parser <* endOfInput)
{-# INLINE parseIPv6 #-}

-- -------------------------------------------------------------------------- --
-- Port Numbers

newtype Port = Port Word16
    deriving (Eq, Ord, Generic)
    deriving anyclass (Hashable, NFData)
    deriving newtype (Show, Real, Integral, Num, Bounded, Enum)

readPortBytes :: MonadThrow m => B8.ByteString -> m Port
readPortBytes = parseBytes "port" portParser
{-# INLINE readPortBytes #-}

portToText :: Port -> T.Text
portToText = sshow
{-# INLINE portToText #-}

portFromText :: MonadThrow m => T.Text -> m Port
portFromText = readPortBytes . T.encodeUtf8
{-# INLINE portFromText #-}

-- -------------------------------------------------------------------------- --
-- Hostnames

data Hostname
    = HostnameName (CI.CI B8.ByteString)
    | HostnameIPv4 (CI.CI B8.ByteString)
    | HostnameIPv6 (CI.CI B8.ByteString)
    deriving (Eq, Ord, Generic)
    deriving anyclass (Hashable, NFData)

instance Show Hostname where
    show = B8.unpack . hostnameBytes

readHostnameBytes :: MonadThrow m => B8.ByteString -> m Hostname
readHostnameBytes b = parseBytes "hostname" parser b
  where
    parser = hostParser <* endOfInput >>= \case
        HostTypeName -> return $! HostnameName (CI.mk b)
        HostTypeIPv4 -> return $! HostnameIPv4 (CI.mk b)
        HostTypeIPv6 -> return $! HostnameIPv6 (CI.mk b)
{-# INLINE readHostnameBytes #-}

localhost :: Hostname
localhost = HostnameName "localhost"
{-# INLINE localhost #-}

-- | Using explicit IP addresses and not to "localhost" greatly improves
-- networking performance and Mac OS X.
--
localhostIPv4 :: Hostname
localhostIPv4 = HostnameIPv4 "127.0.0.1"
{-# INLINE localhostIPv4 #-}

-- | Using explicit IP addresses and not to "localhost" greatly improves
-- networking performance and Mac OS X.
--
localhostIPv6 :: Hostname
localhostIPv6 = HostnameIPv6 "::1"
{-# INLINE localhostIPv6 #-}

anyIpv4 :: Hostname
anyIpv4 = HostnameIPv4 "0.0.0.0"
{-# INLINE anyIpv4 #-}

loopback :: Hostname
loopback = HostnameIPv4 "127.0.0.1"
{-# INLINE loopback #-}

broadcast :: Hostname
broadcast = HostnameIPv4 "255.255.255.255"
{-# INLINE broadcast #-}

isPrivateHostname :: Hostname -> Bool
isPrivateHostname (HostnameIPv4 ip) = isPrivateIp (read $ B8.unpack $ CI.original ip)
isPrivateHostname h
    | h == localhost = True
    | h == localhostIPv4 = True
    | h == localhostIPv6 = True
    | otherwise = False

isReservedHostname :: Hostname -> Bool
isReservedHostname (HostnameIPv4 ip) = isReservedIp (read $ B8.unpack $ CI.original ip)
isReservedHostname h = isPrivateHostname h

ip2ip :: IPv4 -> IP.IPv4
ip2ip (i0, i1, i2, i3) = toIPv4 $ int <$> [i0, i1, i2, i3]
{-# INLINE ip2ip #-}

isLocalIp :: IPv4 -> Bool
isLocalIp i =
    isMatchedTo ip $ makeAddrRange (toIPv4 [127,0,0,0]) 8
  where
    ip = ip2ip i

isPrivateIp :: IPv4 -> Bool
isPrivateIp i = or
    [ isMatchedTo ip $ makeAddrRange (toIPv4 [10,0,0,0]) 8
    , isMatchedTo ip $ makeAddrRange (toIPv4 [172,16,0,0]) 12
    , isMatchedTo ip $ makeAddrRange (toIPv4 [192,168,0,0]) 16
    ]
  where
    ip = ip2ip i

isReservedIp :: IPv4 -> Bool
isReservedIp i = isLocalIp i || isPrivateIp i || or
    [ isMatchedTo ip $ makeAddrRange (toIPv4 [0,0,0,0]) 8
    , isMatchedTo ip $ makeAddrRange (toIPv4 [100,64,0,0]) 10
    , isMatchedTo ip $ makeAddrRange (toIPv4 [169,254,0,0]) 16
    , isMatchedTo ip $ makeAddrRange (toIPv4 [192,0,0,0]) 24
    , isMatchedTo ip $ makeAddrRange (toIPv4 [192,0,2,0]) 24
    , isMatchedTo ip $ makeAddrRange (toIPv4 [192,88,99,0]) 24
    , isMatchedTo ip $ makeAddrRange (toIPv4 [192,18,0,0]) 15
    , isMatchedTo ip $ makeAddrRange (toIPv4 [198,51,100,0]) 24
    , isMatchedTo ip $ makeAddrRange (toIPv4 [203,0,113,0]) 24
    , isMatchedTo ip $ makeAddrRange (toIPv4 [224,0,0,0]) 4
    , isMatchedTo ip $ makeAddrRange (toIPv4 [240,0,0,0]) 4
    , isMatchedTo ip $ makeAddrRange (toIPv4 [255,255,255,255]) 32
    ]
  where
    ip = ip2ip i

hostnameBytes :: Hostname -> B8.ByteString
hostnameBytes (HostnameName b) = CI.original b
hostnameBytes (HostnameIPv4 b) = CI.original b
hostnameBytes (HostnameIPv6 b) = CI.original b
{-# INLINE hostnameBytes #-}

hostnameToText :: Hostname -> T.Text
hostnameToText = T.decodeUtf8 . hostnameBytes
{-# INLINE hostnameToText #-}

hostnameFromText :: MonadThrow m => T.Text -> m Hostname
hostnameFromText = readHostnameBytes . T.encodeUtf8
{-# INLINE hostnameFromText #-}

unsafeHostnameFromText :: HasCallStack => T.Text -> Hostname
unsafeHostnameFromText = fromJuste . hostnameFromText
{-# INLINE unsafeHostnameFromText #-}

-- -------------------------------------------------------------------------- --
-- Hostname Pattern Synonyms

pattern HostName :: CI.CI B8.ByteString -> Hostname
pattern HostName n <- HostnameName n

pattern HostIPv4 :: IPv4 -> Hostname
pattern HostIPv4 i <- (viewIPv4 -> Just i)
  where
    HostIPv4 i = HostnameIPv4 (CI.mk $ sshow i)

pattern HostIPv6 :: IPv6 -> Hostname
pattern HostIPv6 i <- (viewIPv6 -> Just i)
  where
    HostIPv6 i = HostnameIPv6 (CI.mk $ sshow i)

{-# COMPLETE HostIPv4, HostIPv6, HostName #-}

viewIPv4 :: Hostname -> Maybe IPv4
viewIPv4 (HostnameIPv4 bytes) = parseIPv4 $ CI.original bytes
viewIPv4 _ = Nothing

viewIPv6 :: Hostname -> Maybe IPv6
viewIPv6 (HostnameIPv6 bytes) = parseIPv6 $ CI.original bytes
viewIPv6 _ = Nothing

-- -------------------------------------------------------------------------- --
-- Host Addresses

data HostAddress = HostAddress
    { _hostAddressHost :: !Hostname
    , _hostAddressPort :: !Port
    }
    deriving (Show, Eq, Ord, Generic)
    deriving anyclass (Hashable, NFData)

makeLenses ''HostAddress

hostAddressBytes :: HostAddress -> B8.ByteString
hostAddressBytes a = host <> ":" <> sshow (_hostAddressPort a)
  where
    ha = _hostAddressHost a
    host = case ha of
        HostnameIPv6 _ -> "[" <> hostnameBytes ha <> "]"
        _ -> hostnameBytes ha
{-# INLINE hostAddressBytes #-}

readHostAddressBytes :: MonadThrow m => B8.ByteString -> m HostAddress
readHostAddressBytes bytes = parseBytes "hostaddress" (hostAddressParser bytes) bytes

-- | Parser a host address. The input bytestring isn't used for parsing but for
-- the constructing the reslt HostAddress.
--
hostAddressParser :: B8.ByteString -> Parser HostAddress
hostAddressParser b = HostAddress
    <$> hostnameParser'
    <* ":"
    <*> portParser
  where
    host = B8.init $ fst $ B8.breakEnd (== ':') b
    hostnameParser'
        = HostnameName (CI.mk host) <$ hostNameParser
        <|> HostnameIPv4 (CI.mk host) <$ ipV4Parser
        <|> HostnameIPv6 (CI.mk $ B8.init $ B8.tail host) <$ "[" <* ipV6Parser <* "]"
        <?> "host"

hostAddressToText :: HostAddress -> T.Text
hostAddressToText = T.decodeUtf8 . hostAddressBytes
{-# INLINE hostAddressToText #-}

hostAddressFromText :: MonadThrow m => T.Text -> m HostAddress
hostAddressFromText = readHostAddressBytes . T.encodeUtf8
{-# INLINE hostAddressFromText #-}

unsafeHostAddressFromText :: HasCallStack => T.Text -> HostAddress
unsafeHostAddressFromText = fromJuste . hostAddressFromText
{-# INLINE unsafeHostAddressFromText #-}

isPrivateHostAddress :: HostAddress -> Bool
isPrivateHostAddress (HostAddress n _) = isPrivateHostname n
{-# INLINE isPrivateHostAddress #-}

isReservedHostAddress :: HostAddress -> Bool
isReservedHostAddress (HostAddress n _) = isReservedHostname n
{-# INLINE isReservedHostAddress #-}

#ifdef VERSION_aeson
-- -------------------------------------------------------------------------- --
-- Aeson Instances

eitherFromText
    :: (T.Text -> Either SomeException a)
    -> T.Text
    -> Either String a
eitherFromText p = either f return . p
  where
    f e = Left $ case fromException e of
        Just (HostAddressParserException err) -> T.unpack err
        _ -> displayException e
{-# INLINE eitherFromText #-}

deriving newtype instance ToJSON Port
deriving newtype instance FromJSON Port

instance ToJSON HostAddress where
    toJSON o = object
        [ "hostname" .= _hostAddressHost o
        , "port" .= _hostAddressPort o
        ]
    {-# INLINE toJSON #-}

instance FromJSON HostAddress where
    parseJSON = withObject "HostAddress" $ \o -> HostAddress
        <$> o .: "hostname"
        <*> o .: "port"
    {-# INLINE parseJSON #-}

instance ToJSON Hostname where
    toJSON = toJSON . hostnameToText
    {-# INLINE toJSON #-}

instance FromJSON Hostname where
    parseJSON = withText "Hostname"
        $! either fail return . eitherFromText hostnameFromText
    {-# INLINE parseJSON #-}

#endif

#ifdef VERSION_configuration_tools
-- -------------------------------------------------------------------------- --
-- Configuration Tools Support

prefixLong :: HasName f => Maybe String -> String -> Mod f a
prefixLong prefix l = long $ maybe "" (<> "-") prefix <> l

suffixHelp :: Maybe String -> String -> Mod f a
suffixHelp suffix l = help $ l <> maybe "" (" for " <>) suffix

textReader :: (T.Text -> Either SomeException a) -> ReadM a
textReader p = eitherReader $ first show . p . T.pack
{-# INLINE textReader #-}

-- | Simple options parser for Port
--
pPort :: Maybe String -> O.Parser Port
pPort service = O.option (textReader portFromText)
    % prefixLong service "port"
    <> suffixHelp service "port number"
{-# INLINE pPort #-}

-- | Simpe option parser for Hostname
--
pHostname :: Maybe String -> O.Parser Hostname
pHostname service = O.option (textReader hostnameFromText)
    % prefixLong service "hostname"
    <> suffixHelp service "hostname"
{-# INLINE pHostname #-}

instance FromJSON (HostAddress -> HostAddress) where
    parseJSON = withObject "HostAddress" $ \o -> id
        <$< hostAddressHost ..: "hostname" % o
        <*< hostAddressPort ..: "port" % o
    {-# INLINE parseJSON #-}

-- | Configuration tools option parser for HostAddress
--
pHostAddress :: Maybe String -> MParser HostAddress
pHostAddress service = id
    <$< hostAddressHost .:: pHostname service
    <*< hostAddressPort .:: pPort service

-- | Simple Option parser for HostAddress
--
pHostAddress' :: Maybe String -> O.Parser HostAddress
pHostAddress' service = HostAddress <$> pHostname service <*> pPort service

#endif

#ifdef VERSION_QuickCheck
-- -------------------------------------------------------------------------- --
-- Arbitrary Values

-- TODO should we exclude network, broadcast, otherwise special values?

-- | Arbitary IPv4 addresses
--
arbitraryIpV4 :: Gen Hostname
arbitraryIpV4 = HostnameIPv4 . CI.mk . B8.intercalate "." . fmap sshow
    <$> replicateM 4 (arbitrary :: Gen Word8)

-- | Arbitary IPv6 addresses
--
arbitraryIpV6 :: Gen Hostname
arbitraryIpV6 = HostnameIPv6 . CI.mk . B8.intercalate ":" . fmap sshow
    <$> replicateM 8 (arbitrary :: Gen Word8)

-- | Arbitary domain names
--
arbitraryDomainName :: Gen Hostname
arbitraryDomainName = sized $ \n -> resize (min n 254)
    . fmap (HostnameName . mconcat . L.intersperse ".")
    $ (<>)
        <$> listOf (arbitraryDomainLabel False)
        <*> vectorOf 1 (arbitraryDomainLabel True)

-- TODO add frequency or used sized to yield a better distribution

-- | Arbitary domain labels
--
arbitraryDomainLabel :: Bool -> Gen (CI.CI B8.ByteString)
arbitraryDomainLabel isTop = sized $ \n -> resize (min n 63)
    $ CI.mk . B8.pack <$> oneof
        [ vectorOf 1 (if isTop then letter else letterOrDigit)
        , foldM (\l a -> (l <>) <$> a) []
            [ vectorOf 1 (if isTop then letter else letterOrDigit)
            , listOf letterOrDigitOrHyphen
            , vectorOf 1 letterOrDigit
            ]
        ]
  where
    letter = elements $ ['a'..'z'] <> ['A'..'Z']
    letterOrDigit = elements $ ['a'..'z'] <> ['A'..'Z'] <> ['0'..'9']
    letterOrDigitOrHyphen = elements $ ['a'..'z'] <> ['A'..'Z'] <> ['-']

-- | Arbitrary port numbers
--
arbitraryPort :: Gen Port
arbitraryPort = Port <$> arbitrary

instance Arbitrary Port where
    arbitrary = arbitraryPort

-- | Arbitrary host names
--
arbitraryHostname :: Gen Hostname
arbitraryHostname = oneof
    [ arbitraryIpV4
    , arbitraryIpV4
    , arbitraryDomainName
        --  Note that not every valid domain name is also a valid host name.
        --  Generally, a hostname has at least one associated IP address.
        --  Also, syntactic restriction apply for certain top-level domains.
    , pure (HostnameName "localhost")
    , pure localhost
    ]

instance Arbitrary Hostname where
    arbitrary = arbitraryHostname

-- | Arbitrary host adresses
--
arbitraryHostAddress :: Gen HostAddress
arbitraryHostAddress = HostAddress <$> arbitrary <*> arbitrary

instance Arbitrary HostAddress where
    arbitrary = arbitraryHostAddress

-- -------------------------------------------------------------------------- --
-- Properties

prop_readHostAddressBytes :: HostAddress -> Property
prop_readHostAddressBytes a = readHostAddressBytes (hostAddressBytes a) === Just a

prop_readHostnameBytes :: Hostname -> Property
prop_readHostnameBytes h = readHostnameBytes (hostnameBytes h) === Just h

properties :: [(String, Property)]
properties =
    [ ("readHostnameBytes", property prop_readHostnameBytes)
    , ("readHostAddressBytes", property prop_readHostAddressBytes)
    ]
#endif
