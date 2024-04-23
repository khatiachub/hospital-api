using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.Blazor;
using System.Runtime.Intrinsics.X86;
using Newtonsoft.Json;

namespace hospital_api.Model
{
    public class CalendarModel
    {
            [Key]
            public int? id { get; set; }
            public string[]? userId { get; set; }
            public string? doctorId { get; set; }
            public DateTime? start { get; set; }
            public DateTime? endDate { get; set; }
            public string? title { get; set; }
            public bool? isBooked { get; set; }
            public string? color { get; set; }
            public ICollection<Event>? Events { get; set; }
        
    }
    public class Event
    {
        [Key]
        public int? id { get; set; }
        public string? userId { get; set; }
        public string? description{ get; set; }
        public DateTime? start { get; set; }
        public DateTime? endDate { get; set; }
        public bool? isBooked { get; set; }
        public int calendarModelId { get; set; }

    }

}




