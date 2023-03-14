using _18_E_LEARN.DataAccess.Data.Context;
using _18_E_LEARN.DataAccess.Data.IRepository;
using _18_E_LEARN.DataAccess.Data.Models.Courses;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace _18_E_LEARN.DataAccess.Data.Repository
{
    public class CourseRepository : ICourseRepository
    {
        public async Task Create(Course model)
        {
            using (var _context = new AppDbContext())
            {
                await _context.Courses.AddAsync(model);
                await _context.SaveChangesAsync();
            }
        }
        public async Task Update(Course model)
        {
            using (var _context = new AppDbContext())
            {
                _context.Courses.Update(model);
                await _context.SaveChangesAsync();
            }
        }
        public async Task Delete(Course model)
        {
            using (var _context = new AppDbContext())
            {
                _context.Courses.Remove(model);
                await _context.SaveChangesAsync();
            }
        }

        public async Task<IEnumerable<Course>> GetAllAsync()
        {
            using (var _context = new AppDbContext())
            {
                IEnumerable<Course> courses = await _context.Courses.ToListAsync();
                foreach (var course in courses)
                {
                    course.CategoryName = await _context.Categories.Where(c => c.Id == course.CategoryId).Select(c => c.Name).FirstOrDefaultAsync();
                }
                return courses;
            }
        }

        public async Task<Course?> GetByName(string name)
        {
            using (var _context = new AppDbContext())
            {
                var course = await _context.Courses.Where(c => c.Name == name).FirstOrDefaultAsync();
                return course;
            }
        }

        public async Task<Course?> GetByIdAsync(int id)
        {
            using (var _context = new AppDbContext())
            {
                var course = await _context.Courses.Where(c => c.Id == id).FirstOrDefaultAsync();
                return course;
            }
        }
    }
}
