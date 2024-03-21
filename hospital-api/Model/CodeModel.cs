using System.ComponentModel;

namespace hospital_api.Model
{
    public class CodeModel
    {
        public string? Email { get; set; }
        public string? Code { get; set; }
        public string? NewCode { get; set; }
        public string? Token { get; set; }
        public DateTime Time { get; set; }
    }
}
