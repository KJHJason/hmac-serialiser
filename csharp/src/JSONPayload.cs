using System;
using System.Collections.Generic;
using System.Text.Json;

namespace HMACSerialiser
{
    public class JSONPayload
    {
        public readonly JsonDocument jsonDoc;

        public JSONPayload(JsonDocument jsonDoc)
        {
            this.jsonDoc = jsonDoc;
        }

        /// <summary>
        /// Used for payloads like [1, 2, 3], which does not have a key. Hence, this method is used to obtain the array payload.
        /// </summary>
        /// <typeparam name="T">The resulting type to convert the data to after retreiving from the JSON payload</typeparam>
        /// <returns>The value from the JSON payload if it exists and is the correct type. Otherwise, returns the default value of the provided type like 0 for int</returns>
        public T Get<T>()
            => Get<T>(null, default);

        /// <summary>
        /// Get a value from the JSON payload with a default fallback value
        /// </summary>
        /// <typeparam name="T">The resulting type to convert the data to after retreiving from the JSON payload</typeparam>
        /// <param name="key">The key in the JSON payload</param>
        /// <returns>The value from the JSON payload if it exists and is the correct type. Otherwise, returns the default value of the provided type like 0 for int</returns>
        public T Get<T>(string key)
            => Get<T>(key, default);

        /// <summary>
        /// Get a value from the JSON payload with a custom fallback value
        /// </summary>
        /// <typeparam name="T">The resulting type to convert the data to after retreiving from the JSON payload</typeparam>
        /// <param name="key">The key in the JSON payload</param>
        /// <param name="fallback">The custom fallback value to use if it does not exist or is not of the expected type</param>
        /// <returns>The value from the JSON payload or the custom fallback value</returns>
        public T Get<T>(string key, T fallback)
        {
            if (string.IsNullOrEmpty(key))
            {
                // Usually used for obtaining the array payload like ["a", "b", "c"]
                try
                {
                    return JsonSerializer.Deserialize<T>(jsonDoc.RootElement.GetRawText());
                }
                catch (Exception)
                {
                    return fallback;
                }
            }

            if (!jsonDoc.RootElement.TryGetProperty(key, out JsonElement value))
                return fallback;

            if (value.ValueKind == JsonValueKind.Null)
                return fallback;

            try
            {
                return JsonSerializer.Deserialize<T>(value.GetRawText());
            }
            catch (Exception)
            {
                return fallback;
            }
        }
    }
}
