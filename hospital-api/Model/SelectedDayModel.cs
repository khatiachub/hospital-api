using System.ComponentModel.DataAnnotations;

namespace hospital_api.Model
{
    public class SelectedDayModel
    {
        [Key]
        public int? id { get; set; }
        public DateTime? selectedDate { get; set; }
    }
}
