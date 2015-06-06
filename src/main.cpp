/* (c) Copyright 2011-2014 Felipe Magno de Almeida
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <gts/array_pat_section.hpp>
#include <gts/packet_sequence.hpp>
#include <gts/psi_pointer_sequence.hpp>
#include <gts/transport_packet_concept.hpp>
#include <gts/algorithm/table_id_from_section.hpp>
#include <gts/programs/program_concept.hpp>
#include <gts/program.hpp>
#include <gts/iterators/forward_iterator_concept.hpp>
#include <gts/iterators/bidirectional_iterator_concept.hpp>
#include <gts/iterators/algorithm/for_each.hpp>

#include <boost/filesystem/path.hpp>
#include <boost/program_options.hpp>

#include <fstream>
#include <iostream>

int main(int argc, char* argv[])
{
  boost::filesystem::path ts_file;
  boost::program_options::options_description description
    ("Allowed options");
  description.add_options()
    ("help", "produce this help message")
    ("ts", boost::program_options::value<std::string>(), "TS file to analyze");
  try
  {
    boost::program_options::variables_map vm;
    boost::program_options::store(boost::program_options::parse_command_line(argc, argv, description), vm);
    boost::program_options::notify(vm);

    if(vm.count("ts"))
    {
      ts_file = vm["ts"].as<std::string>();
    }
    else
    {
      std::cout << description << std::endl;
      return 1;
    }
  }
  catch(boost::program_options::unknown_option const&)
  {
    std::cout << "Unknown option. Try the following:\n" << description << std::endl;
    return 1;
  }

  std::filebuf filebuf;
  filebuf.open(ts_file.string().c_str(), std::ios::in);
  if(!filebuf.is_open())
  {
    std::cout << "Coudln't open file: " << ts_file.string() << std::endl;
    return -1;
  }  

  int skipped_bytes = 0;
  while(filebuf.sgetc() != EOF && filebuf.sgetc() != 0x47)
  {
    ++skipped_bytes;
    filebuf.snextc();
  }

  assert(filebuf.sgetc() == EOF || filebuf.sgetc() == 0x47);
  if(filebuf.sgetc() == EOF)
    std::cout << "No packets" << std::endl;
  else
  {
    std::cout << "Skipped " << skipped_bytes << " to find first packet" << std::endl;

    unsigned char buffer[188];

    typedef gts::packet_sequence<unsigned char const*> packet_type;
    BOOST_CONCEPT_ASSERT((gts::TransportPacketConcept<packet_type>));
    typedef gts::program<packet_type> program_type;
    BOOST_CONCEPT_ASSERT((gts::programs::ProgramConcept<program_type>));
    program_type program;

    assert(program.has_es_buffer(0u)); // has PMT

    do
    {
      std::streamsize s = 0, c = 0;
      while((s = filebuf.sgetn(reinterpret_cast<char*>(buffer), 188 - c)) && s + c != 188)
      {
        if(s == 0)
          return 0;
        else
          c += s;
      }

      packet_type packet(buffer, buffer + 188);

      std::cout << "value of first byte: " << (unsigned int)buffer[0] << std::endl;
      
      BOOST_CONCEPT_ASSERT((gts::sequences::SequenceConcept<packet_type>));

      typedef packet_type::sync_byte_iterator sync_byte_iterator;
      typedef gts::sequences::result_of::end<packet_type>::type end_iterator;
      sync_byte_iterator sync_byte = gts::sequences::begin(packet);
      end_iterator end = gts::sequences::end(packet);
      if(sync_byte != end && *sync_byte == 0x47)
      {
        typedef packet_type::transport_error_indicator_iterator transport_error_indicator_iterator;
        transport_error_indicator_iterator transport_error_indicator = ++sync_byte;
        if(transport_error_indicator != end)
        {
          std::cout << "transport error indicator: " << *transport_error_indicator << std::endl;

          typedef packet_type::payload_unit_start_indicator_iterator payload_unit_start_indicator_iterator;
          payload_unit_start_indicator_iterator payload_unit_start_indicator = ++transport_error_indicator;

          assert(payload_unit_start_indicator != end);
          if(payload_unit_start_indicator != end)
          {
            std::cout << "payload unit start indicator: " << *payload_unit_start_indicator << std::endl;

            typedef packet_type::transport_priority_iterator transport_priority_iterator;
            transport_priority_iterator transport_priority = ++payload_unit_start_indicator;
            if(transport_priority != end)
            {
              std::cout << "transport priority: " << *transport_priority << std::endl;
              typedef packet_type::pid_iterator pid_iterator;
              pid_iterator pid = ++transport_priority;
        
              if(pid != end)
              {
                std::cout << "PID: " << *pid << std::endl;

                std::cout << "demuxing packet" << std::endl;

                if(program.has_es_buffer(*pid))
                  program.es_buffer(*pid).push_packet(packet);

                typedef packet_type::transport_scrambling_control_iterator transport_scrambling_control_iterator;
                transport_scrambling_control_iterator transport_scrambling_control = ++pid;
                assert(transport_scrambling_control != end);
                if(transport_scrambling_control != end)
                {
                  std::cout << "transport scrambling control: " << *transport_scrambling_control << std::endl;
                  typedef packet_type::adaptation_field_control_iterator adaptation_field_control_iterator;
                  adaptation_field_control_iterator adaptation_field_control = ++transport_scrambling_control;
                  assert(adaptation_field_control != end);

                  if(adaptation_field_control != end)
                  {
                    std::cout << "adaptation field control: " << *adaptation_field_control << std::endl;

                    typedef packet_type::continuity_counter_iterator continuity_counter_iterator;
                    continuity_counter_iterator continuity_counter = ++adaptation_field_control;
                    assert(continuity_counter != end);
                    if(continuity_counter != end)
                    {
                      std::cout << "continuity counter: " << *continuity_counter << std::endl;
              
                      typedef packet_type::adaptation_field_iterator adaptation_field_iterator;
                      adaptation_field_iterator adaptation_field = ++continuity_counter;

                      if(adaptation_field != end)
                      {
                        if(*adaptation_field_control >= 2)
                        {
                          std::cout << "has adaptation field!" << std::endl;
                          typedef gts::adaptation_field_sequence<unsigned char const*> adaptation_field_type;
                          BOOST_CONCEPT_ASSERT((gts::sequences::SequenceConcept<adaptation_field_type>));
                          adaptation_field_type adaptation_field_seq = *adaptation_field;

                          typedef adaptation_field_type::adaptation_field_length_iterator
                            adaptation_field_length_iterator;
                          typedef adaptation_field_type::end_iterator end_iterator;
                          adaptation_field_length_iterator adaptation_field_length = adaptation_field_seq.begin();
                          end_iterator end = adaptation_field_seq.end();
                          assert(adaptation_field_length != end);
                          std::cout << "== field length: " << *adaptation_field_length << std::endl;

                          typedef adaptation_field_type::discontinuity_indicator_iterator
                            discontinuity_indicator_iterator;
                          discontinuity_indicator_iterator discontinuity_indicator = ++adaptation_field_length;
                          if(discontinuity_indicator != end)
                          {
                            std::cout << "== discontinuity indicator " << *discontinuity_indicator << std::endl;

                            typedef adaptation_field_type::random_access_indicator_iterator
                              random_access_indicator_iterator;
                            random_access_indicator_iterator random_access_indicator = ++discontinuity_indicator;
                            if(random_access_indicator != end)
                            {
                              std::cout << "== random access indicator: " << *random_access_indicator << std::endl;
                            }
                          }
                        }
                        typedef packet_type::payload_iterator payload_iterator;
                        payload_iterator payload = ++adaptation_field;
                        if(payload != end)
                        {
                          if(*adaptation_field_control & 0x1)
                          {
                            std::pair<unsigned char const*, unsigned char const*> range
                              = *payload;
                            std::cout << "Has payload " << std::distance(range.first, range.second)
                                      << " bytes" << std::endl;
                          }
                        }
                        else
                        {
                          std::cout << "no payload" << std::endl;
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
      else
      {
        std::cout << "Error, no sync byte, byte: " << (unsigned int)*sync_byte << std::endl;
      }
    }
    while(true);
  }
}

