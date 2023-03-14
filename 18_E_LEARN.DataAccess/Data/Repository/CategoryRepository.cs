using _18_E_LEARN.DataAccess.Data.Context;
using _18_E_LEARN.DataAccess.Data.IRepository;
using _18_E_LEARN.DataAccess.Data.Models.Categories;
using _18_E_LEARN.DataAccess.Data.Models.Courses;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace _18_E_LEARN.DataAccess.Data.Repository
{
    public class CategoryRepository : ICategoryRepository
    {
        public async Task<List<Category>> GetAllAsync()
        {
            using (var _context = new AppDbContext())
            {
                List<Category> categories = await _context.Categories.ToListAsync();
                return categories;
            }
        }

        public async Task<Category> GetByIdAsync(int id)
        {
            using (var _context = new AppDbContext())
            {
                Category result = await _context.Categories.FirstOrDefaultAsync(c => c.Id == id);
                return result;
            }
        }

        public async Task<Category> GetByNameAsync(string name)
        {
            using (var _context = new AppDbContext())
            {
                Category result = await _context.Categories.FirstOrDefaultAsync(c => c.Name == name);
                return result;
            }
        }
        public async Task Create(Category model)
        {
            using (var _context = new AppDbContext())
            {
                await _context.Categories.AddAsync(model);
                await _context.SaveChangesAsync();
            }
        }

        public string Update(Category category)
        {
            using (var _context = new AppDbContext())
            {
                var result = _context.Categories.Update(category);
                var saveResult = _context.SaveChanges();
                return result.State.ToString();
            }
        }
        public async Task Delete(Category category)
        {
            using (var _context = new AppDbContext())
            {
                var courses = await _context.Courses.Where(c => c.CategoryId == category.Id).ToListAsync();
                foreach (var c in courses)
                {
                    c.CategoryId = null;
                }
                _context.Courses.UpdateRange(courses);
                _context.Categories.Remove(category);
                await _context.SaveChangesAsync();
            }
        }
    }
}
