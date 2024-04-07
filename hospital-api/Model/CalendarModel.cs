namespace hospital_api.Model
{
    public class CalendarModel
    {
        public string Id { get; set; }
        public string UserId { get; set; }
        public string DoctorId { get; set; }
        public DateTime? Date { get; set; }
        public string Description { get; set; }
}
}
