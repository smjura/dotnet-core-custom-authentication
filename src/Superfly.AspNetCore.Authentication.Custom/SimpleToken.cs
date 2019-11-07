using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.Text;

namespace Superfly.AspNetCore.Authentication.Custom
{
    /// <summary>
    /// This class represents the token format for the SimpleWebToken.
    /// </summary>
    public class SimpleToken : SecurityToken
    {
        public static DateTime SwtBaseTime = new DateTime(1970, 1, 1, 0, 0, 0, 0); // per SWT psec

        NameValueCollection _properties;

        SecurityKey _signingKey;
        string _serializedToken;

        /// <summary>
        /// Initializes a new instance of the <see cref="SimpleWebToken"/> class.
        /// This is an internal constructor that is only called from the <see cref="SimpleWebTokenHandler"/> when reading a token received from the wire.
        /// </summary>
        /// <param name="properties">The collection representing all the key value pairs in the token.</param>
        /// <param name="serializedToken">The serialized form of the token.</param>
        internal SimpleToken(NameValueCollection properties, string serializedToken)
            : this(properties)
        {
            _serializedToken = serializedToken;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SimpleWebToken"/> class.
        /// </summary>
        /// <param name="properties">The collection representing all the key value pairs in the token.</param>
        public SimpleToken(NameValueCollection properties)
        {
            if (properties == null)
            {
                throw new ArgumentNullException("properties");
            }

            _properties = properties;
        }

        /// <summary>
        /// Gets the Id of the token.
        /// </summary>
        /// <value>The Id of the token.</value>
        public override string Id
        {
            get
            {
                return _properties[SimpleTokenConstants.Id];
            }
        }

        /// <summary>
        /// Gets the time from when the token is valid.
        /// </summary>
        /// <value>The time from when the token is valid.</value>
        public override DateTime ValidFrom
        {
            get
            {
                string validFrom = _properties[SimpleTokenConstants.ValidFrom];
                return GetTimeAsDateTime(String.IsNullOrEmpty(validFrom) ? "0" : validFrom);
            }
        }

        /// <summary>
        /// Gets the time when the token expires.
        /// </summary>
        /// <value>The time up to which the token is valid.</value>
        public override DateTime ValidTo
        {
            get
            {
                string expiryTime = _properties[SimpleTokenConstants.ExpiresOn];
                return GetTimeAsDateTime(String.IsNullOrEmpty(expiryTime) ? "0" : expiryTime);
            }
        }

        /// <summary>
        /// Gets the Audience for the token.
        /// </summary>
        /// <value>The audience of the token.</value>
        public string Audience
        {
            get
            {
                return _properties[SimpleTokenConstants.Audience];
            }
        }

        /// <summary>
        /// Gets the signature for the token.
        /// </summary>
        /// <value>The signature for the token.</value>
        public string Signature
        {
            get
            {
                return _properties[SimpleTokenConstants.Signature];
            }
        }

        /// <summary>
        /// Gets the serialized form of the token if the token was created from its serialized form by the token handler.
        /// </summary>
        /// <value>The serialized form of the token.</value>
        public string SerializedToken
        {
            get
            {
                return _serializedToken;
            }
        }

        public override SecurityKey SecurityKey => null;

        public override SecurityKey SigningKey { get => _signingKey; set => _signingKey = value; }

        public override string Issuer => _properties[SimpleTokenConstants.Issuer];


        /// <summary>
        /// Creates a copy of all key value pairs of the token.
        /// </summary>
        /// <returns>A copy of all the key value pairs in the token.</returns>
        public NameValueCollection GetAllProperties()
        {
            return new NameValueCollection(_properties);
        }

        /// <summary>
        /// Converts the time in seconds to a <see cref="DateTime"/> object based on the base time 
        /// defined by the Simple Web Token.
        /// </summary>
        /// <param name="expiryTime">The time in seconds.</param>
        /// <returns>The time as a <see cref="DateTime"/> object.</returns>
        protected virtual DateTime GetTimeAsDateTime(string expiryTime)
        {
            long totalSeconds = 0;
            if (!long.TryParse(expiryTime, out totalSeconds))
            {
                throw new SecurityTokenException("Invalid expiry time. Expected the time to be in seconds passed from 1 January 1970.");
            }

            long maxSeconds = (long)(DateTime.MaxValue - SwtBaseTime).TotalSeconds - 1;
            if (totalSeconds > maxSeconds)
            {
                totalSeconds = maxSeconds;
            }

            return SwtBaseTime.AddSeconds(totalSeconds);
        }
    }
}
