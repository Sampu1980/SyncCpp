#include "DbiCliAdapter/InfoTable.h"

#include <utility>
#include <iomanip>
#include <iterator>
#include <boost/io/ios_state.hpp>
#include <boost/format.hpp>

InfoTable::InfoTable(std::vector<std::string> columnNames, std::string emptyCell)
    : myColumnNames(std::move(columnNames))
    , myEmptyCellValue(std::move(emptyCell))
    , myNumberOfRows(0)
{
    for(auto const& name : myColumnNames)
    {
        // insert one column for each specified column name
        myColumns[name];
    }
}

InfoTable& InfoTable::addRow()
{
    for(auto& column : myColumns)
    {
        column.second.push_back(myEmptyCellValue);
    }

    ++myNumberOfRows;
    return *this;
}

InfoTable& InfoTable::addValue(std::string const& columnName, std::string const& value)
{
    auto position = myColumns.find(columnName);

    if(position == myColumns.end())
    {
        throw std::logic_error(boost::str(boost::format("Column '%1%' not found in info table columns") % columnName));
    }
    else if(myNumberOfRows == 0)
    {
        throw std::logic_error("No rows added to the table yet");
    }
    else
    {
        position->second[myNumberOfRows - 1] = value;
    }

    return *this;
}

void InfoTable::dumpTo(std::ostream& out)
{
    char const tableSep = '|';
    boost::io::ios_base_all_saver ifs(out); // on destruction will restore the stream's flags

    try
    {
        std::map<std::string, size_t> const columnWidths = computeColumnWidths();

        // print header
        out << tableSep;

        for(auto const& columnName : myColumnNames)
        {
            auto columnSize = columnWidths.at(columnName);

            out << std::setw(columnSize) << columnName << tableSep;
        }

        out << std::endl;

        printSeparatorLine(out, tableSep, columnWidths);

        // print rows
        for(size_t rowNumber = 0; rowNumber != myNumberOfRows; ++rowNumber)
        {
            out << tableSep;

            for(auto const& columnName : myColumnNames)
            {
                auto columnSize = columnWidths.at(columnName);

                out << std::setfill(' ') << std::setw(columnSize) << myColumns.at(columnName).at(rowNumber) << tableSep;
            }

            out << std::endl;
        }

        printSeparatorLine(out, tableSep, columnWidths);
    }
    catch(std::exception const& e)
    {
        out << "Caught an exception: " << e.what() << std::endl;
    }
}

void InfoTable::printSeparatorLine(std::ostream& out, char tableSep,
                                   std::map<std::string, size_t> const& columnWidths) const
{
    boost::io::ios_base_all_saver ifs(out); // on destruction will restore the stream's flags
    out << tableSep;

    for(auto const& columnName : this->myColumnNames)
    {
        auto columnSize = columnWidths.at(columnName);

        out << std::setfill('-') << std::setw(columnSize) << '-' << tableSep;
    }

    out << std::endl;
}

std::map<std::string, size_t> InfoTable::computeColumnWidths() const
{
    std::map<std::string, size_t> columnWidths;

    for(auto const& column : myColumns)
    {
        auto columnName = column.first;
        auto columnVector = column.second;

        size_t columnSize = columnName.length();

        for(auto const& line : column.second)
        {
            columnSize = std::max(columnSize, line.length());
        }

        columnWidths[columnName] = columnSize;
    }

    return columnWidths;
}

InfoTable InfoTable::sortBy(std::string const& columnName)
{
    auto position = myColumns.find(columnName);

    InfoTable table(myColumnNames, myEmptyCellValue);

    if(position == myColumns.end())
    {
        throw std::logic_error(boost::str(boost::format("Column '%1%' not found in info table columns") % columnName));
    }
    else
    {
        std::vector<std::string> rows = position->second;
        std::sort(rows.begin(), rows.end());

        std::map<std::string, std::vector<std::string>> columnsCopy = myColumns;

        for(auto const& row : rows)
        {
            table.addRow();

            // find out the index of the (sorted) column in the key row, in our copy of the original table
            std::vector<std::string>& keyColumn = columnsCopy.at(columnName);
            auto it = std::find(keyColumn.begin(), keyColumn.end(), row);
            auto columnIndex = std::distance(keyColumn.begin(), it);

            // fill in the columns in the new sorted table by accessing the correct row of the old table (using the index we found)
            for(auto const& currentColumnName : myColumnNames)
            {
                std::vector<std::string>& column = columnsCopy.at(currentColumnName);
                auto currentColumnEntry = column.begin();
                std::advance(currentColumnEntry, columnIndex);

                table.addValue(currentColumnName, *currentColumnEntry);
                column.erase(currentColumnEntry); // remove the values we copied over, from each column in our copy of the old table
            }
        }
    }

    return table;
}
