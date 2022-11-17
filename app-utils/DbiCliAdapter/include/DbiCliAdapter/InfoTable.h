#ifndef INFOTABLE_H
#define INFOTABLE_H

#include <vector>
#include <string>
#include <map>

/**
 * @brief Auxiliar class to build a table of (usually debug) information, for later dumping/printing to a std::ostream.
 *
 * The constructor takes a vector or (ordered) column names and an optional value to display if the value of a particular cell was not set.
 * addRow must be called for each row of data to be added to the table (including the first one).
 * addValue should be called to fill in the value of a concrete cell in the row being defined @see addRow
 *
 * When all of the data was added to the InfoTable instance, dumpTo can be called to build a textual table adequate for printing in a
 * monospaced terminal or text file.
 *
 */
class InfoTable
{
    public:
        /**
         * @brief Custom contructor
         * @param columnNames vector identifying the table columns
         * @param emptyCell string to be set in the cell when is empty
         */
        InfoTable(std::vector<std::string> columnNames, std::string emptyCell = "N/A");

        /**
         * @brief Adds a new row to the table.
         * Note that this must be called, including for the first row of the table
         * (unless you *really* want an empty table with just the header/column names row).
         * @return a reference to the same table instance. This allows addRow calls to be chained with addValue calls.
         *
         * Chaining calls will look like table.addRow().addValue("column name", "column value");
         */
        InfoTable& addRow();

        /**
         * @brief Set the value of a cell in the last added row.
         * @see addRow
         * @param columnName The column name where the value should go. Must exactly match one of column names defined in the constructor.
         * @param value The text that cell should contain
         * @throw std::logic_error if the column name is not one of the column names specified in the constructor.
         * @return a reference to the same table instance. This allows addValue calls to be chained with other addValue calls.
         * Chaining calls will look like table.addValue("column 1", "value 1").addValue("column 2", "value 2");
         */
        InfoTable& addValue(std::string const& columnName, std::string const& value);

        void dumpTo(std::ostream& out);

        /**
         * @brief Sorts the table using the values in the specified column as keys.
         * Currently this method will throw an std::runtime_error if the values in the specified column contains any duplicates.
         *
         * @param columnName The column to use as key for sorting the lines of the table.
         * @return a *copy* of the table, after being sorted.
         * This allows chaining calls to sortBy, and will produce different versions of the table.
         * A typical use would be:
         * table = table.sortBy("shelf").sortBy("slot")
         */
        InfoTable sortBy(std::string const& columnName);

    private:
        std::map<std::string, size_t> computeColumnWidths() const;
        void printSeparatorLine(std::ostream& out, char tableSep, std::map<std::string, size_t> const& columnWidths) const;

        std::vector<std::string> myColumnNames;
        std::map<std::string, std::vector<std::string>> myColumns;
        std::string myEmptyCellValue;
        size_t myNumberOfRows;
};

#endif
