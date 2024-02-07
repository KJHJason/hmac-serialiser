using System;
using System.Text.Json;

namespace HMACSerialiser
{
    public class JSONPayload
    {
        public readonly JsonDocument jsonDocument;

        public JSONPayload(JsonDocument jsonDocument)
        {
            this.jsonDocument = jsonDocument;
        }

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
            if (!jsonDocument.RootElement.TryGetProperty(key, out JsonElement value))
                return fallback;

            if (value.ValueKind == JsonValueKind.Undefined || value.ValueKind == JsonValueKind.Null)
                return fallback;

            if (typeof(T) == typeof(int))
            {
                if (value.ValueKind == JsonValueKind.Number)
                    return (T)(object)value.GetInt32();
                return fallback;
            }

            if (typeof(T) == typeof(long))
            {
                if (value.ValueKind == JsonValueKind.Number)
                    return (T)(object)value.GetInt64();
                return fallback;
            }

            if (typeof(T) == typeof(bool))
            {
                if (value.ValueKind == JsonValueKind.True || value.ValueKind == JsonValueKind.False)
                    return (T)(object)value.GetBoolean();
                 return fallback;
            }

            if (typeof(T) == typeof(float))
            {
                if (value.ValueKind == JsonValueKind.Number)
                    return (T)(object)value.GetSingle();
                 return fallback;
            }

            if (typeof(T) == typeof(double))
            {
                if (value.ValueKind == JsonValueKind.Number)
                    return (T)(object)value.GetDouble();
                return fallback;
            }

            if (typeof(T) == typeof(decimal))
            {
                if (value.ValueKind == JsonValueKind.Number)
                    return (T)(object)value.GetDecimal();
                return fallback;
            }

            if (typeof(T) == typeof(string))
            {
                if (value.ValueKind == JsonValueKind.String)
                    return (T)(object)value.GetString();
                return fallback;
            }

            if (typeof(T) == typeof(DateTime))
            {
                if (value.ValueKind == JsonValueKind.String && DateTime.TryParse(value.GetString(), out DateTime dateTime))
                    return (T)(object)dateTime;
                return fallback;
            }

            // Handle nested JSON objects or arrays
            try
            {
                var jsonSerializerOptions = new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                };
                var json = value.GetRawText();
                return JsonSerializer.Deserialize<T>(json, jsonSerializerOptions);
            }
            catch (Exception)
            {
                return fallback;
            }
        }
    }
}
