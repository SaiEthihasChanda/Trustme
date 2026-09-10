package app.trustme;

/**
 * Just enough JSON to read one string field out of a response.
 *
 * <p>Hand-rolled so the library has no JSON dependency, but it still unescapes
 * properly: secret values legitimately contain quotes, backslashes and newlines.
 */
final class Json {

    private Json() {}

    static String string(String json, String key) {
        if (json == null) return null;
        String needle = "\"" + key + "\"";
        int at = json.indexOf(needle);
        if (at < 0) return null;

        int i = at + needle.length();
        while (i < json.length() && Character.isWhitespace(json.charAt(i))) i++;
        if (i >= json.length() || json.charAt(i) != ':') return null;
        i++;
        while (i < json.length() && Character.isWhitespace(json.charAt(i))) i++;
        if (i >= json.length() || json.charAt(i) != '"') return null;
        i++;

        StringBuilder out = new StringBuilder();
        while (i < json.length()) {
            char c = json.charAt(i);
            if (c == '"') return out.toString();
            if (c != '\\') {
                out.append(c);
                i++;
                continue;
            }
            if (i + 1 >= json.length()) break;
            char esc = json.charAt(i + 1);
            switch (esc) {
                case '"': out.append('"'); i += 2; break;
                case '\\': out.append('\\'); i += 2; break;
                case '/': out.append('/'); i += 2; break;
                case 'b': out.append('\b'); i += 2; break;
                case 'f': out.append('\f'); i += 2; break;
                case 'n': out.append('\n'); i += 2; break;
                case 'r': out.append('\r'); i += 2; break;
                case 't': out.append('\t'); i += 2; break;
                case 'u':
                    if (i + 5 >= json.length()) return null;
                    out.append((char) Integer.parseInt(json.substring(i + 2, i + 6), 16));
                    i += 6;
                    break;
                default:
                    return null;
            }
        }
        return null;
    }
}
