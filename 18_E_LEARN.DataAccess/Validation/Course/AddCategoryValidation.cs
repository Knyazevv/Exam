using _18_E_LEARN.DataAccess.Data.ViewModels.Course;
using FluentValidation;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace _18_E_LEARN.DataAccess.Validation.Course
{
    public class AddCategoryValidation : AbstractValidator<AddCategoryVM>
    {
        public AddCategoryValidation()
        {
            RuleFor(r => r.Name).NotEmpty().MaximumLength(16);
        }
    }
}
